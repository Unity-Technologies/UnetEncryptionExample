#pragma once


#include <cstdint>



struct PacketHeader
{
	// The HMAC of the entire rest of the packet.
	static const size_t HMAC_LENGTH = 32;
	uint8_t hmac[HMAC_LENGTH];

	uint8_t version;

	static const uint8_t CURRENT_VERSION = 1;

	//
	// We HMAC the packet with encrypted data as the final step before sending.
	//
	// A legitimate question is, why do we HMAC the encrypted data rather than the plaintext?
	// We use the Encrypt-then-MAC design described here:
	// https://crypto.stackexchange.com/a/205
	//
	// One advantage is that the recipient check the HMAC before even *attempting* to decrypt the data,
	// which protects the actual decryption algorithm from theoretical attacks using modified ciphertext.
	//
	// A second advantage is that the data fed into the HMAC algorithm is already in ciphertext form
	// (i.e. relatively garbled compared with the plaintext input, which is likely to have patterns).
	// This helps to protect against any theoretical weaknesses where somebody could obtain the input from the hash value
	// (i.e. all they would obtain is the encrypted data).
	//

	// The UUID of the KeySet to use (so the recipient knows which key to decrypt with).
	// This is sent in the packet unencrypted.  It is not secret.
	// This is fine because the keys themselves never travel over UDP.
	// Only people who have the corresponding HMAC key can generate a packet for this UUID.
	static const size_t UUID_LENGTH = 16;
	uint8_t key_uuid[UUID_LENGTH];

	// The start of the actual packet payload.
	uint8_t data[0];
};

static_assert(sizeof(PacketHeader) == PacketHeader::HMAC_LENGTH + sizeof (PacketHeader::version) + PacketHeader::UUID_LENGTH, "Unexpected padding for PacketHeader.");
