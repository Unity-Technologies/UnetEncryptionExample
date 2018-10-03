

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <string.h>
#include <vector>
#include <algorithm>
#include <uuid/uuid.h>
#include <thread>
#include <mutex>

#include "Packet.h" // From ../../Shared/



// Interesting links:


// HMAC the plaintext or the ciphertext?
//
// https://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac


using namespace std;

typedef void (*LogFunc) (const char * str);
static LogFunc g_logCB = nullptr;



struct KeySet
{
	uuid_t uuid;

	int serial;

	static int s_next_serial;

	static const size_t KEY_LEN = 32;
	uint8_t encryption_key [KEY_LEN];

	static const size_t HMAC_KEY_LEN = 32; // ?
	uint8_t hmac_key [HMAC_KEY_LEN];

	static const size_t IV_LEN = 16;
	uint8_t iv [IV_LEN];
};

int KeySet::s_next_serial = 1;

typedef std::vector<KeySet> KeyStore;
static KeyStore g_keySet;

// separate struct to use connectionID to retrieve keyset
struct KeyUuidForConnection {
	int connection_id;
	uuid_t uuid;
};

typedef std::vector<KeyUuidForConnection> ConnectionKeyStore;
static ConnectionKeyStore g_keysForConnections;

// UUID for next connection
static uuid_t g_uuidForNextConnection;

// Mutex for modifying or accessing any of the above data structures.
typedef std::mutex mutex_t;
static mutex_t g_mutex;
typedef std::lock_guard<mutex_t> lock_t;

extern "C" int SetLogFunc (LogFunc f)
{
	g_logCB = f;
}

static void Log (const char * format, ...)
{
	va_list args;
	va_start (args, format);
	char * str = 0;
	size_t len = 0;
	FILE * f = 0;

	if (!g_logCB)
		goto cleanup;
	
	f = open_memstream (&str, &len);
	if (!f)
		goto cleanup;

	vfprintf (f, format, args);
	fflush (f); // puts a null and the end of the buffer
	g_logCB (str);

cleanup:

	if (f) {
		fclose (f);
		f = 0;
	}

	free (str);
	va_end(args);
}


// Serialization / Deserialization of UUIDs.
//
// On Linux this is nothing more than a memcpy.
// (On Windows there's a bit of endian-swapping)
//
// However it's a healthy concept to keep these functions
// rather than calling memcpy within Encrypt and Decrypt.

static void WriteBytesFromUuid (void * dst, const uuid_t u)
{
	memcpy (dst, u, sizeof (uuid_t));
}

static void ReadUuidFromBytes (uuid_t u, const void * src)
{
	memcpy (u, src, sizeof (uuid_t));
}


extern "C" int UnetEncryptionInit ()
{
	return 0;
	// This function is more interesting on other platforms.
}


extern "C" int AddConnectionKeys (
	const char * uuid_str,
	uint8_t * encryption_key,
	uint32_t encryption_key_length,
	uint8_t * hmac_key,
	uint32_t hmac_key_length,
	uint8_t * iv,
	uint32_t iv_length)
{
	lock_t lock (g_mutex);

	KeySet k;
	memset (&k, 0, sizeof (KeySet));

	uuid_t parsed_uuid;
	int ok = uuid_parse(uuid_str, parsed_uuid);
	if (ok != 0)
	{
		Log (
			"Failed to parse caller's string \"%s\" as a UUID.",
			(uuid_str ? uuid_str : "(null)"));
		return 1;
	}

	// Make sure we don't have a KeySet with this UUID already.
	auto it = std::find_if (
		g_keySet.begin(),
		g_keySet.end(),
		[=] (const KeySet& k) {
			return !uuid_compare(k.uuid, parsed_uuid);
		});
	bool already_got = it != g_keySet.end();
	if (already_got)
		return 1;

	memcpy (k.uuid, parsed_uuid, sizeof(k.uuid));

	if (encryption_key_length != KeySet::KEY_LEN)
		return 1;
	memcpy (k.encryption_key, encryption_key, sizeof (k.encryption_key));

	if (hmac_key_length != KeySet::HMAC_KEY_LEN)
		return 1;
	memcpy (k.hmac_key, hmac_key, sizeof (k.hmac_key));

	if (iv_length != KeySet::IV_LEN)
		return 1;
	memcpy (k.iv, iv, sizeof (k.iv));

	k.serial = KeySet::s_next_serial++;
	if (KeySet::s_next_serial == 0)
		++KeySet::s_next_serial;

	g_keySet.push_back (k);
	return 0;
}


extern "C" int SetUuidForNextConnection (const char * uuid_str)
{
	lock_t lock (g_mutex);
	uuid_t new_uuid;
	int ok = uuid_parse(uuid_str, new_uuid);
	if (ok != 0) {
		Log (
			"SetUuidForNextConnection failed to parse \"%s\" as a UUID.",
			(uuid_str ? uuid_str : "(null)"));
		return 1;
	}

	uuid_copy (g_uuidForNextConnection, new_uuid);
	return 0;
}


extern "C" int RemoveConnectionKeys (const char * uuid_str)
{
	lock_t lock (g_mutex);
	uuid_t uuid;
	int ok = uuid_parse(uuid_str, uuid);
	if (ok != 0) {
		Log (
			"RemoveConnectionKeys failed to parse \"%s\" as a UUID.",
			(uuid_str ? uuid_str : "(null)"));
		return 1;
	}

	g_keySet.erase (
		std::remove_if(
			g_keySet.begin(),
			g_keySet.end(),
			[&] (const KeySet & k) {
				return ! uuid_compare (k.uuid, uuid);
			}),
		g_keySet.end()
	);
	return 0;
}

extern "C" int Encrypt(
	void * payload,
	int payload_len,
	void * dest,
	int & dest_len,
	int connection_id,
	bool isConnect)
{
	lock_t lock (g_mutex);

	// This is what we'll return.
	// Nonzero means failure.
	// We assume failure, and set to zero on success.
	int ret = 1;

	// dest_len is the capacity on the way in,
	// and the amount used on the way out.
	//
	// Grab the input value now so we don't get confused.
	const size_t dest_capacity = (size_t) dest_len;

	EVP_CIPHER_CTX * ctx = 0;
	PacketHeader * p = reinterpret_cast<PacketHeader*>(dest);
	unsigned char * put = p->data;

	// The amount of data generated by the most recent EncryptUpdate/EncryptFinal call.
	int used = 0;

	unsigned char * hmac = NULL;
	const uint8_t * hmac_input_start;
	size_t hmac_input_length;

	// Is dest_capacity large enough?
	//
	// Block padding rounds up to the next block.
	// If the AES encryption
	const size_t AES_BLOCK_SIZE = 16;
	size_t bytes_required =
		((payload_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE
		+
		sizeof (PacketHeader);
	if (dest_capacity < bytes_required) {
		Log (
			"Require %d to encrypt %d, but only have %d\n",
			bytes_required, payload_len, dest_capacity);
		return 1;
	}

	// Find the KeyUuidForConnection for this connection id.
	// If this is the connect, use g_uuidForNextConnection.
	if (isConnect) {
		// Remove anything we currently have for this connection.
		g_keysForConnections.erase (
			std::remove_if (
				g_keysForConnections.begin(),
				g_keysForConnections.end(),
				[=] (const KeyUuidForConnection & k4c) {
					return k4c.connection_id == connection_id;
				}),
			g_keysForConnections.end());
		KeyUuidForConnection k4c;
		memset(&k4c, 0 , sizeof(k4c));
		k4c.connection_id = connection_id;
		uuid_copy (k4c.uuid, g_uuidForNextConnection);
		g_keysForConnections.push_back (k4c);
	}

	auto it = std::find_if (
		g_keysForConnections.begin(),
		g_keysForConnections.end(),
		[&] (const KeyUuidForConnection& ku4c) {
			return ku4c.connection_id == connection_id;
		});
	bool have_k4c = (it != g_keysForConnections.end());
	if (!have_k4c) {
		Log (
			"Do not have KeyUuidForConnection for connection %d\n",
			connection_id);
		return 1;
	}

	// 2. find KeySet with UUID obtained
	auto keyIt = std::find_if(
		g_keySet.begin(),
		g_keySet.end(),
		[&](const KeySet& ks) {
		return !uuid_compare(ks.uuid, it->uuid);
	});
	bool have_key = keyIt != g_keySet.end();
	if (!have_key) {
		Log (
			"Have UUID for connection %d, but no KeySet.",
			connection_id);
		return 1;
	}


	KeySet keys = *keyIt;
	// This is a deep copy rather than a pointer/reference.
	// This is deliberate.
	// The EVP_ functions receive things like the key
	// and IV as a non-const unsigned char *,
	// so it's possible that they modify them.

	// EVP_ functions return nonzero for "success".
	int ok = 1;

	ctx = EVP_CIPHER_CTX_new();
	if (!ctx) {
		Log ("EVP_CIPHER_CTX_new failed in Encrypt\n");
		goto cleanup;
	}

	ok = EVP_EncryptInit (
		ctx,
		EVP_aes_256_cbc(),
		keys.encryption_key,
		keys.iv);
	if (!ok) {
		Log ("EVP_EncryptInit failed\n");
		goto cleanup;
	}

	ok = EVP_EncryptUpdate (
		ctx,
		put,
		&used,
		(const unsigned char *) payload,
		payload_len);
	if (!ok) {
		Log ("EVP_EncryptUpdate with %d bytes failed\n", payload_len);
		goto cleanup;
	}

	put += used;
	used = 0;

	ok = EVP_EncryptFinal (
		ctx,
		put,
		&used);
	if (!ok) {
		Log ("EncryptFinal failed\n");
		goto cleanup;
	}
	put += used;
	used = 0;

	// copy uuid into packet
	WriteBytesFromUuid (p->key_uuid, keys.uuid);

	// packet header Version
	p->version = PacketHeader::CURRENT_VERSION;

	// HMAC the rest of the packet
	// We encrypt the whole packet; header plus data.
	// The only bit we don't HMAC is the space to store the HMAC itself.
	hmac_input_start = ((uint8_t*)p) + sizeof(p->hmac);
	hmac_input_length = (put - p->data) + (sizeof(PacketHeader) - sizeof(p->hmac));
	hmac = HMAC(
		EVP_sha256(),
		keys.hmac_key,
		sizeof (keys.hmac_key),
		hmac_input_start,
		hmac_input_length,
		p->hmac,
		NULL);
	if (!hmac) {
		Log ("Failed to HMAC %d bytes of packet data.", hmac_input_length);
		goto cleanup;
	}

	// Success.
	dest_len = (int) (sizeof(PacketHeader) + (put - p->data));
	//                              Header + Payload
	ret = 0;

cleanup:

	if (ctx) {
		EVP_CIPHER_CTX_free (ctx);
		ctx = 0;
	}

	return ret;
}



extern "C" int Decrypt(
	void * payload,
	int payload_len,
	void * dest,
	int & dest_len,
	int & context)
{
	lock_t lock (g_mutex);

	int ret = 1; // Our return value.
	int ok = 0; // Value from EVP_* functions.

	// dest_len is the capacity of the buffer going in,
	// and the number of bytes actually written on return.
	// Grab a const copy of the capacity, to avoid confusion.
	const size_t dest_capacity = (size_t) dest_len;

	// The received data must be AT LEAST the size of a PacketHeader,
	// even if there is not a single extra byte.
	if (payload_len < sizeof (PacketHeader))
	{
		Log(
			"Error: Packet size %d is smaller than minimum %d\n",
			payload_len, sizeof (PacketHeader));
		return 1;
	}


	const size_t ciphertext_len = payload_len - sizeof (PacketHeader);
	const PacketHeader * p = reinterpret_cast<const PacketHeader*>(payload);

	if (!p) {
		Log ("Error: Null packet payload (or failed to reinterpret_cast).");
		return 1;
	}

	if (p->version != PacketHeader::CURRENT_VERSION) {
		Log("Error: PacketHeader version check failed.  Expected %d, received %d\n",
			PacketHeader::CURRENT_VERSION, p->version);
		return 1;
	}

	// convert packet header uuid to uuid_t
	uuid_t received_uuid;
	ReadUuidFromBytes (received_uuid, p->key_uuid);

	// Find the KeySet with the matching UUID.
	auto it = std::find_if (
		g_keySet.begin(),
		g_keySet.end(),
		[=] (const KeySet& k) {
			return !uuid_compare(k.uuid, received_uuid);
		});
	bool found_key = it != g_keySet.end();
	if (!found_key) {
		Log("Error: KeySet not found for received UUID.");
		// The packet's bytes might not even be a legal UUID,
		// so we don't even attempt to unparse it and include it in the log.
		return 1;
	}

	KeySet keys = *it;
	// Intentionally a full copy.  See encoding function for explanation.


	// Check the HMAC before attempting decryption.
	uint8_t * hmac_input_start = ((uint8_t*)p) + sizeof(p->hmac);
	size_t hmac_input_length = payload_len - sizeof(p->hmac);
	unsigned char local_hmac [EVP_MAX_MD_SIZE];
	unsigned int local_hmac_len = 0;

	unsigned char * hmac = HMAC (
		EVP_sha256(),
		keys.hmac_key,
		sizeof (keys.hmac_key),
		hmac_input_start,
		hmac_input_length,
		local_hmac,
		&local_hmac_len);
	// There are two things to check:
	// 1) Did we even manage to locally compute the HMAC at all?
	// 2) Does the locally-computed one match the one in the packet?
	bool hmac_completed = hmac == local_hmac;
	if (!hmac_completed) {
		Log ("Failed to compute local HMAC of received packet.");
		return 1;
	}
	bool hmac_matches =
		local_hmac_len == PacketHeader::HMAC_LENGTH &&
		! memcmp (local_hmac, p->hmac, local_hmac_len);
	if (!hmac_matches) {
		Log ("Locally-computed HMAC did not match packet.");
		return 1; // The HMACs were different.
	}


	// Now actually perform decryption.
	EVP_CIPHER_CTX * ctx = NULL;

	// Both EVP_DecryptUpdate and EVP_DecryptFinal can produce more bytes.
	// "put" is a put pointer that progresses through "dest".
	// "used" is the number of bytes produced by the most-recent call.
	unsigned char * put = (unsigned char *) dest;
	int used = 0;

	ctx = EVP_CIPHER_CTX_new ();
	if (!ctx) {
		Log ("EVP_CIPHER_CTX_new returned null\n");
		goto cleanup;
	}

	ok = EVP_DecryptInit (
		ctx,
		EVP_aes_256_cbc(),
		keys.encryption_key,
		keys.iv);
	if (!ok) {
		Log ("EVP_DecryptInit failed\n");
		goto cleanup;
	}

	ok = EVP_DecryptUpdate (
		ctx,
		put,
		&used,
		p->data,
		ciphertext_len);
	if (!ok) {
		Log ("EVP_DecryptUpdate with %d bytes failed.", ciphertext_len);
		goto cleanup;
	}
	put += used;
	used = 0;

	ok = EVP_DecryptFinal (
		ctx,
		put,
		&used);
	if (!ok) {
		Log ("EVP_DecryptFinal failed.\n");
		goto cleanup;
	}
	put += used;
	used = 0;

	// Write our "out" values and set ret to success.
	dest_len = put - (unsigned char *) dest;
	context = keys.serial;
	ret = 0;

cleanup:
	if (ctx) {
		EVP_CIPHER_CTX_free (ctx);
	}

	return ret;
}


extern "C" void ConnectionIdAssigned (int context, unsigned short connectionId)
{
	lock_t lock (g_mutex);

	// Erase any existing assignment for this connectionId.
	g_keysForConnections.erase (
		std::remove_if(
			g_keysForConnections.begin(),
			g_keysForConnections.end(),
			[=] (const KeyUuidForConnection & k4c) {
				return k4c.connection_id == connectionId;
			}),
		g_keysForConnections.end());


	// Find the KeySet with the given context.
	auto it = std::find_if (
		g_keySet.begin(),
		g_keySet.end(),
		[=] (const KeySet & k) {
			return k.serial == context;
		});

	bool found = it != g_keySet.end();
	if (!found) {
		Log ("ConnectionIdAssigned failed to find KeySet with id %d", context);
		return;
	}

	KeyUuidForConnection k4c;
	uuid_copy (k4c.uuid, it->uuid);
	k4c.connection_id = connectionId;
	g_keysForConnections.push_back (k4c);
}





extern "C" unsigned short SafeMaxPacketSize(unsigned short mtu)
{
	lock_t lock (g_mutex);
	// Subtract the size of the header.
	mtu -= sizeof(PacketHeader);

	// Round down to next block size.
	// (If mtu is already on a block boundary, round down to the next one after that)
	const size_t BLOCK_SIZE = 16;
	mtu = ((mtu-1) / BLOCK_SIZE) * BLOCK_SIZE;

	return mtu;
}

