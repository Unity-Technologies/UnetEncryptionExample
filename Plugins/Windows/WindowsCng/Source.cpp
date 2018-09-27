
#include <Windows.h>
#include <map>
#include <utility>
#include <bcrypt.h>
#include <string>
#include <stdlib.h>
#include <sstream>
#include <vector>
#include <algorithm>
#include <rpc.h>

#ifdef _XBOX_ONE
#include <xdk.h>
#include <wrl.h>
#endif


#include "Packet.h"

using namespace std;

#pragma comment(lib, "Rpcrt4.lib")

// Microsoft's own examples define this, e.g. https://docs.microsoft.com/en-us/windows/desktop/seccng/creating-a-hash-with-cng
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)



// All the keys, etc. required to communicate with a peer.
//
// This is what the game receives from the matchmaker.
// The game registers it with the plugin via unet_add_connection_keys.
//
// Consists of:
//
//  * UUID identifier for this key set.
//  * A Windows BCRYPT_KEY_HANDLE to the encryption key.
//    This is a "resource" handle that requires careful lifetime management,
//    which means this struct uses a move constructor and move assignment.
//  * 256 bit key for SHA-256 HMAC.
//  * 16 byte (128 bit, 1 block) Initialization Vector.
//
//
// MOVE CONSTRUCTORS
// =================
//
// Because this type acts as the resource-owner of the BRCRYPT_KEY_HANDLE,
// we use move semantics.
//
// TODO: An improvement would be to make the BCRYPT_KEY_HANDLE private
// and take it in the constructor.
//
struct KeySet
{
	UUID uuid;

	// This is the id with which we communicate with the Untiy runtime.
	int serial;

	static int s_next_serial;

	static const size_t HMAC_KEY_LENGTH = 32; // 256 bit.
	uint8_t hmac_key_bytes[32];

	static const size_t IV_LENGTH = 16;
	uint8_t iv[IV_LENGTH];


	KeySet(BCRYPT_KEY_HANDLE handle) :
		encryption_key_handle(handle)
	{

		// The other members can stay uninitialized.
	}

	~KeySet()
	{
		if (encryption_key_handle) {
			BCryptDestroyKey(encryption_key_handle);
			encryption_key_handle = NULL;
		}
	}

	// Move constructor and assignment.
	KeySet(KeySet && k) :
		uuid(k.uuid),
		serial (k.serial),
		encryption_key_handle(std::exchange(k.encryption_key_handle, (BCRYPT_KEY_HANDLE)NULL))
	{
		memcpy(hmac_key_bytes, k.hmac_key_bytes, HMAC_KEY_LENGTH);
		memcpy(iv, k.iv, IV_LENGTH);
	}

	KeySet & operator = (KeySet && k)
	{
		std::swap(encryption_key_handle, k.encryption_key_handle);
		uuid = k.uuid;
		serial = k.serial;
		memcpy(hmac_key_bytes, k.hmac_key_bytes, sizeof(hmac_key_bytes));
		memcpy(iv, k.iv, sizeof(iv));
		return *this;
	}

	BCRYPT_KEY_HANDLE GetEncryptionKeyHandle() const {
		return encryption_key_handle;
	}

private:

	// BCryptEncrypt takes a BCRYPT_KEY_HANDLE rather than a raw byte array.
	// Assuming that it takes some non-negligable effort to create a BCRYPT_KEY_HANDLE from the raw bytes,
	// we do so just once when the caller initially supplies them.
	BCRYPT_KEY_HANDLE encryption_key_handle;


	KeySet(const KeySet& k) = delete;
	KeySet & operator = (const KeySet & k) = delete;
};

int KeySet::s_next_serial = 1;


typedef std::vector<KeySet> KeyStore;
static KeyStore g_keys;


// When we're SENDING packets, Unity tells us the UNet connection_id that this packet is for.
// We use that to look up the KeySet.
struct KeyUuidForConnection {
	int connection_id;
	UUID uuid; // Use this to look up within g_keys.
};

typedef std::vector<KeyUuidForConnection> ConnectionKeyStore;

static ConnectionKeyStore g_keysForConnections;


// TODO: Function to call "reserve" on above vectors.


static UUID g_uuidForNextConnection;


// Handles to BCrypt algorithms.
static BCRYPT_ALG_HANDLE g_algo = 0;
static BCRYPT_ALG_HANDLE g_sha256 = 0;


// Logging
// =======
//
// User provides a function that takes a string.
// Code here writes to it using an ostream.

typedef void(*LogFunc) (const char * str);
static LogFunc g_log_cb = 0;


// Streambuf implementation for calling user's logging callback.
class LogBuf : public std::basic_stringbuf<char>
{
public:
	virtual ~LogBuf() {
		sync();
	}
protected:
	int sync();
};

int LogBuf::sync()
{
	string s = str();
	str("");
	if (s.empty())
		return 0;
	if (g_log_cb)
		g_log_cb(s.c_str());
	return 0;
}

class LogStream : public std::basic_ostream<char>
{
public:
	LogStream() : std::basic_ostream<char>(&m_buf) {}
private:
	LogBuf m_buf;
};

// Plugin code writes to this:
static LogStream g_log;

extern "C" __declspec(dllexport) void SetLogFunc(LogFunc f)
{
	g_log_cb = f;
	g_log << "Set logging func.  This should be the first message you see." << endl;
}



// UUID parsing.
// Windows' functions operate on wide-strings, but anything passed in from Mono is UTF-8.
static HRESULT parse_uuid_from_utf8(UUID * u, const char * str)
{
	size_t len = strlen(str);

	const size_t EXPECTED_SIZE = 36;
	if (len != EXPECTED_SIZE)
		return E_INVALIDARG;

	// Microsoft function requires a wide-string,
	// and also for the UUID to be surrounded with { and }
	const size_t WIDE_STR_LENGTH = EXPECTED_SIZE + 3; // +3 for  {, }, and null terminator.
	wchar_t w[WIDE_STR_LENGTH];
	w[WIDE_STR_LENGTH - 1] = 0;

	const size_t OPEN_BRACE_IDX = 0, CLOSE_BRACE_IDX = WIDE_STR_LENGTH - 2;
	size_t num_wide = 0;
	mbstowcs_s(
		&num_wide,
		&w[OPEN_BRACE_IDX + 1],
		EXPECTED_SIZE + 1,
		str,
		EXPECTED_SIZE);
	w[OPEN_BRACE_IDX] = L'{';
	w[CLOSE_BRACE_IDX] = L'}';

	HRESULT result = IIDFromString(w, u);
	return result;
}





extern "C" __declspec(dllexport) int UnetEncryptionInit()
{
	NTSTATUS err = 0;
	
	err = BCryptOpenAlgorithmProvider(&g_algo, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (!NT_SUCCESS(err))
		goto fail;

	err = BCryptOpenAlgorithmProvider(&g_sha256, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG);
	if (!NT_SUCCESS(err))
		goto fail;

	return 0;
fail:
	if (g_algo) {
		BCryptCloseAlgorithmProvider(g_algo, 0);
		g_algo = 0;
	}
	if (g_sha256) {
		BCryptCloseAlgorithmProvider(g_sha256, 0);
		g_sha256 = 0;
	}
	return -1;
}




extern "C" __declspec(dllexport) int AddConnectionKeys(
	const char * uuid_str,
	uint8_t * encryption_key,
	uint32_t encryption_key_length,
	uint8_t * hmac_key,
	uint32_t hmac_key_length,
	uint8_t * iv,
	uint32_t iv_length)
{
	if (!uuid_str)
		uuid_str = "";

	NTSTATUS err = 0;
	UUID u;

	// UUID
	memset(&u, 0, sizeof(u));
	HRESULT uuid_status = parse_uuid_from_utf8(&u, uuid_str);
	if (uuid_status) {
		g_log << "Failed to parse UUID \"" << uuid_str << "\".  Got error 0x" << hex << uuid_status << dec << endl;
		return 1;
	}

	// Make sure we don't have keys with this user_id.
	auto user_id_it = find_if(
		g_keys.begin(),
		g_keys.end(),
		[&u](const KeySet& x) {
		return x.uuid == u;
	});
	bool have_user_id_already = user_id_it != g_keys.end();
	if (have_user_id_already) {
		g_log << "Already have KeySet with UUID \"" << uuid_str << "\"" << endl;
		return 1;
	}

	// Other sanity checks:

	// HMAC length.
	if (hmac_key_length != KeySet::HMAC_KEY_LENGTH) {
		g_log << "Given an HMAC key of length " << hmac_key_length << ", but require " << KeySet::HMAC_KEY_LENGTH << endl;
		return 1;
	}

	// IV length.
	if (iv_length != KeySet::IV_LENGTH) {
		g_log << "Given an IV of length " << iv_length << ", but require " << KeySet::IV_LENGTH << endl;
		return 1;
	}


	// Encryption key.
	BCRYPT_KEY_HANDLE handle = 0;
	err = BCryptGenerateSymmetricKey(
		g_algo,
		&handle,
		NULL,
		0,
		encryption_key,
		encryption_key_length,
		0);
	if (!NT_SUCCESS(err)) {
		g_log << "BCryptGenerateSymmetricKey with key of " << encryption_key_length << " bytes failed with 0x" << hex << err << dec << endl;
		return -1;
	}

	// Now we can instantiate the KeySet
	KeySet k(handle);

	k.uuid = u;
	memcpy(k.hmac_key_bytes, hmac_key, hmac_key_length);
	memcpy(&k.iv, iv, iv_length);
	k.serial = KeySet::s_next_serial++;
	if (KeySet::s_next_serial == 0)
		++KeySet::s_next_serial;

	g_keys.push_back(std::move(k));
	return 0;
}



extern "C" __declspec(dllexport) int RemoveConnectionKeys(
	const char * uuid_str)
{
	UUID u;
	HRESULT err = parse_uuid_from_utf8(&u, uuid_str);
	if (err)
		return 1;

	// Allow for the possibility of there being more than one KeySet that matches 'u'.
	//
	// It shouldn't happen, but allowing for it makes the code self-healing.

	auto it = std::partition(
		g_keys.begin(),
		g_keys.end(),
		[&](const KeySet & keys) {
		return keys.uuid == u;
	});

	auto dist = std::distance(it, g_keys.end());
	g_log << "Iterator is " << dist << " from end." << endl;

	bool any_to_remove = it != g_keys.end();
	if (any_to_remove)
		g_keys.erase(it, g_keys.end());

	return any_to_remove ? 0 : 2;
}



extern "C" __declspec(dllexport) int SetUuidForNextConnection(const char * uuid_str)
{
	UUID u;
	HRESULT err = parse_uuid_from_utf8(&u, uuid_str);
	if (err)
		return (int)err;
	g_uuidForNextConnection = u;
	return 0;
}



static int do_hmac(uint8_t * dest, const uint8_t * src, size_t len, const uint8_t * key)
{
	const DWORD flags = 0;
	BCRYPT_HASH_HANDLE hash = 0;
	NTSTATUS err = 0;
	int ret = 1; // This is what we'll return.  We set it to 0 once we're sure everything is OK.

	// BCryptCreateHash takes a non-const pointer to the key bytes.
	// So rather than passing in the parameter, we make a stack-based copy
	// and pass that instead.
	uint8_t key_copy[KeySet::HMAC_KEY_LENGTH];
	memcpy(key_copy, key, sizeof(key_copy));

	err = BCryptCreateHash(g_sha256, &hash, NULL, 0, key_copy, KeySet::HMAC_KEY_LENGTH, flags);
	if (!NT_SUCCESS(err)) {
		g_log << "CreateHash failed with 0x" << hex << err << dec << endl;
		goto cleanup;
	}

	// TODO: Could we use a reusable hash object, initialized once?


	err = BCryptHashData(hash, (PUCHAR)src, (ULONG)len, 0);
	if (!NT_SUCCESS(err)) {
		g_log << "BCryptHashData of " << len << " bytes failed with 0x" << hex << err << dec << endl;
		goto cleanup;
	}

	err = BCryptFinishHash(hash, dest, (ULONG)PacketHeader::HMAC_LENGTH, 0);
	if (!NT_SUCCESS(err)) {
		g_log << "BCryptFinishHash failed with 0x" << hex << err << dec << endl;
		goto cleanup;
	}

	ret = 0; // Success!
cleanup:

	BCryptDestroyHash(hash);
	return ret;
}


static void get_uuid_from_bytes(UUID * u, const uint8_t * bytes)
{
	static_assert (sizeof(UUID) == 16, "Unexpected padding in UUID.  get_uuid_from_bytes needs refactor.");
	memcpy(u, bytes, sizeof(UUID));
	u->Data1 = _byteswap_ulong(u->Data1);
	u->Data2 = _byteswap_ushort(u->Data2);
	u->Data3 = _byteswap_ushort(u->Data3);
}

static void put_bytes_from_uuid(uint8_t * dest, const UUID * u)
{
	UUID copy = *u;
	copy.Data1 = _byteswap_ulong(copy.Data1);
	copy.Data2 = _byteswap_ushort(copy.Data2);
	copy.Data3 = _byteswap_ushort(copy.Data3);
	static_assert (sizeof(UUID) == 16, "Unexpected padding in UUID.  put_bytes_from_uuid needs refactor.");
	memcpy(dest, &copy, sizeof(UUID));
}



extern "C" __declspec(dllexport) int __stdcall Decrypt(
	void * payload,
	int payload_len,
	void * dest,
	int & dest_len,
	int & context)
{
	// Keep the input value handy, to avoid confusion.
	const size_t dest_capacity = dest_len;

	NTSTATUS err = 0;
	if (dest_capacity < payload_len)
		return 1;

	PacketHeader * p = reinterpret_cast<PacketHeader*>(payload);
	size_t data_size = payload_len - sizeof(PacketHeader);

	UUID key_uuid;
	get_uuid_from_bytes(&key_uuid, p->key_uuid);

	auto it = std::find_if(
		g_keys.begin(),
		g_keys.end(),
		[&](const KeySet & k) {
		return k.uuid == key_uuid;
	});
	bool have_key = it != g_keys.end();

	if (!have_key) {
		g_log << "Do not have key to decrypt this packet." << endl;
		return 1;
	}
	const KeySet & keys = *it;

	// Before decrypting, HMAC the ciphertext and make sure it matches the packet header.
	uint8_t hmac[PacketHeader::HMAC_LENGTH];
	uint8_t * hmac_input_start = ((uint8_t*)p) + sizeof(p->hmac);
	size_t hmac_input_length = payload_len - sizeof(p->hmac);
	int local_hmac_err = do_hmac(hmac, hmac_input_start, hmac_input_length, keys.hmac_key_bytes);
	if (local_hmac_err) {
		g_log << "Failed to perform local HMAC on received packet: 0x" << hex << local_hmac_err << dec << endl;
		return -1;
	}
	bool hmac_matches = !memcmp(hmac, p->hmac, PacketHeader::HMAC_LENGTH);
	if (!hmac_matches) {
		g_log << "Local HMAC did not agree with received HMAC.  Packet corrupted in-flight." << endl;
		return 1;
	}

	if (p->version != PacketHeader::CURRENT_VERSION) {
		g_log << "Recieved badly-versioned packet.  Expecting " << PacketHeader::CURRENT_VERSION << ", received " << p->version << endl;
		return 1;
	}

	// Decrypt the data into dest.
	DWORD flags = BCRYPT_BLOCK_PADDING;
	ULONG used = 0; // ULONG for BCryptDecrypt.  We'll copy its value into dest_size later.

	// BCryptDecrypt modifies the IV, so use a copy.
	uint8_t iv_copy[KeySet::IV_LENGTH];
	memcpy(iv_copy, &keys.iv, KeySet::IV_LENGTH);
	err = BCryptDecrypt(
		keys.GetEncryptionKeyHandle(),
		p->data,
		(ULONG)data_size,
		NULL,
		iv_copy,
		sizeof(iv_copy),
		(PUCHAR)dest,
		(ULONG)dest_capacity,
		&used,
		flags);
	if (!NT_SUCCESS(err)) {
		g_log << "BCryptDecrypt of " << data_size << " bytes into buffer capacity " << dest_capacity << " failed with 0x" << hex << err << dec << endl;
		return -1;
	}

	dest_len = used;
	context = keys.serial;

	return 0;
}


extern "C" __declspec(dllexport) int __stdcall  Encrypt(
	void * payload,
	int payload_len,
	void * dest,
	int & dest_len,
	int connection_id,
	bool isConnect)
{
	// dest_len is the capacity coming in, and the amount used on exit.
	// Grab the input value to avoid confusion.
	const size_t dest_capacity = dest_len;

	NTSTATUS err = 0;

	// IMPORTANT: Keep the capacity check in the next few lines BEFORE any code that touches "p".

	// Is dest_capacity enough?
	//
	// ciphertext_capacity is dest_capacity minus the size of the header.
	// This is how much encrypted data we can store.
	size_t ciphertext_capacity = dest_capacity - sizeof(PacketHeader);
	const size_t AES_BLOCK_SIZE = 16;
	size_t ciphertext_will_use = ((payload_len / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	bool have_capacity = ciphertext_capacity >= ciphertext_will_use;
	if (!have_capacity) {
		g_log << "Asked to encrypt " << payload_len << " into buffer size " << dest_capacity << ", but will use " << (ciphertext_will_use + sizeof(PacketHeader)) << endl;
		return 1;
	}

	// Find the keys to use.
	//
	// This is a 2-step process.
	// First, find the KeyUuidForConnection corresponding to this connection_id.
	// Then, find the KeySet that corresponds to the UUID found in the previous step.
	//
	// If "isConnect", then use g_uuidForNextConnection.
	if (isConnect) {
		// Remove anything we currently have for this connection.
		g_keysForConnections.erase(
			std::remove_if(
				g_keysForConnections.begin(),
				g_keysForConnections.end(),
				[=](const KeyUuidForConnection & k4c) {
			return k4c.connection_id == connection_id;
		}),
			g_keysForConnections.end());

		KeyUuidForConnection k4c;
		k4c.uuid = g_uuidForNextConnection;
		k4c.connection_id = connection_id;
		g_keysForConnections.push_back(k4c);
	}


	auto it = std::find_if(
		g_keysForConnections.begin(),
		g_keysForConnections.end(),
		[&](const KeyUuidForConnection& key4con) {
		return key4con.connection_id == connection_id;
	});
	bool found_conn_id = it != g_keysForConnections.end();

	if (!found_conn_id) {
		g_log << "Don't have KeyUuidForConnection for connection id " << connection_id << endl;
		return 1;
	}

	// Now try and find the KeySet with that UUID.
	auto keyIt = std::find_if(
		g_keys.begin(),
		g_keys.end(),
		[&](const KeySet& ks) {
		return ks.uuid == it->uuid;
	});

	bool have_key = keyIt != g_keys.end();
	if (!have_key) {
		g_log << "found KeyUuidForConnection, but not KeySet for connection_id " << connection_id << endl;
		return 1;
	}
	const KeySet & keys = *keyIt;

	PacketHeader * const p = reinterpret_cast<PacketHeader*>(dest);

	p->version = PacketHeader::CURRENT_VERSION;

	// BCryptEncrypt modifies the IV that is passed in.
	// So we make a stack-based copy of keys.iv.
	uint8_t iv_copy[KeySet::IV_LENGTH];
	memcpy(iv_copy, &keys.iv, sizeof(iv_copy));

	// Encrypt the payload.
	ULONG used = 0;
	DWORD flags = BCRYPT_BLOCK_PADDING;
	err = BCryptEncrypt(
		keys.GetEncryptionKeyHandle(),
		(PUCHAR)payload,
		(ULONG)payload_len,
		NULL,
		iv_copy,
		sizeof (iv_copy),
		p->data,
		(ULONG)ciphertext_capacity,
		&used,
		flags);
	if (!NT_SUCCESS(err)) {
		g_log << "BCryptEncrypt on " << payload_len << " cleartext bytes into " << ciphertext_capacity << " buffer used " << used << " and returned 0x" << hex << err << dec << endl;
		return -1;
	}

	dest_len = (int)(used + sizeof(PacketHeader));

	put_bytes_from_uuid(p->key_uuid, & keys.uuid);

	// HMAC the entire rest of the packet.
	const uint8_t * hmac_input_start = ((uint8_t*)p) + sizeof(p->hmac);
	size_t hmac_input_length = used + sizeof(PacketHeader) - sizeof(p->hmac);
	int hmac_err = do_hmac(p->hmac, hmac_input_start, hmac_input_length, keys.hmac_key_bytes);
	if (hmac_err) {
		g_log << "Failed to perform HMAC on " << hmac_input_length << " bytes.  Received error 0x" << hex<< hmac_err << dec<< endl;
		return -1;
	}

	return 0;
}


extern "C" __declspec (dllexport) void __stdcall ConnectionDropped(int connection_id)
{
	auto it = std::remove_if(
		g_keysForConnections.begin(),
		g_keysForConnections.end(),
		[=](const KeyUuidForConnection& ku4c) {
		return ku4c.connection_id == connection_id;
	});
	g_keysForConnections.erase(it);
}



extern "C" __declspec(dllexport) unsigned short __stdcall SafeMaxPacketSize(unsigned short mtu)
{
	// Subtract the size of the header.
	mtu -= sizeof(PacketHeader);

	// Round down to next block size.
	// (If mtu is already on a block boundary, round down to the next one after that)
	const size_t BLOCK_SIZE = 16;
	mtu = ((mtu-1) / BLOCK_SIZE) * BLOCK_SIZE;

	return mtu;
}



extern "C" __declspec(dllexport) void __stdcall ConnectionIdAssigned(int context, unsigned short connectionId)
{
	// g_log << "Associating KeySet " << context << " with connection id " << connectionId << endl;


	// Remove any existing association with this connectionId.
	auto remove_it = std::remove_if(
		g_keysForConnections.begin(),
		g_keysForConnections.end(),
		[=](const KeyUuidForConnection & k4c) {
		return k4c.connection_id == connectionId;
	});

	auto num_to_remove = g_keysForConnections.end() - remove_it;
	if (num_to_remove != 0) {
		g_log << "Warning, ConnectionIdAssigned replacing " << num_to_remove << " existing assignments for connection id " << connectionId << endl;
	}

	g_keysForConnections.erase(remove_it, g_keysForConnections.end());

	auto it = std::find_if(
		g_keys.begin(),
		g_keys.end(),
		[=](const KeySet & ks) {
		return ks.serial == context;
	});

	bool ok = it != g_keys.end();
	if (!ok) {
		g_log << "ConnectionIdAssigned with unknown context " << context << endl;
		return;
	}

	KeyUuidForConnection k4c;
	k4c.uuid = it->uuid;
	k4c.connection_id = connectionId;
	g_keysForConnections.push_back(k4c);
}
