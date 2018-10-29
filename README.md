# UnetEncryptionPlugin

This repository contains a reference implementation of a Unet encryption plugin, as well as a very small example Unity project that uses the plugin.


[This is a link](docs/other.md)


## Encryption Plugins:  Required Functions

Encryption plugins must provide the following functions.  These are the functions that will be called by the Unity runtime itself.  Plugins will typically provide _additional_ functions to be called from the User's C# code, for example for registering keys.

### Encrypt

```C
int Encrypt(
	void * payload,
	int payload_len,
	void * dest,
	int & dest_len,
	int connection_id,
	bool isConnect);
```
Perform encryption.  This is called whenever a packet is to be sent.

#### Parameters
* **payload** is the data to be encrypted.
* **payload_len** is the length of the *payload* buffer, in bytes.
* **dest** is the buffer into which the plugin should write the encrypted data.
* **dest_len** is the capacity in bytes of the **dest** buffer.  The plugin must replace this value with the number of bytes _actually written_ into **dest**.
* **connection_id** is the local identifier of the connection.
* **isConnect** is true if this packet is a connection request.  When this is true, the plugin must have been told ahead of time (by game code) which key to use.  When this is false, it is expected that the plugin already has a mapping from this value to a key to use.  See the example plugin for an implementation.

#### Return value

`Encrypt` must return zero on success.  On any other return value, the runtime will drop the packet without sending it.


### Decrypt

```C
int Decrypt(
	void * payload,
	int payload_len,
	void * dest,
	int & dest_len,
	int & key_id)
```
Perform decryption.  This is called whenever a packet is received.

#### Parameters

* **payload** is the received packet.
* **payload_len** is the length in bytes of the **payload** buffer.
* **dest** is the buffer into which the plugin should write the decrypted data.
* **dest_len** is the capacity in bytes of the **dest** buffer.  The plugin must replace this value with the number of bytes _actually written_ into **dest**.
* **key_id** is an integer identifier.  The plugin should write a value that uniquely identifies the decryption key used.  On the server this value will be passed back into `ConnectionIdAssigned` if a new connection is accepted.

#### Return value

`Decrypt` must return zero on success.  On any other return value, the packet is dropped without being processed further.


### SafeMaxPacketSize
```C
unsigned short SaveMaxPacketSize (unsigned short mtu);
```
Modify the maximum transmission unit (MTU).  This is called when the plugin is loaded.  The existing MTU is passed in, and the plugin must return the modified MTU, which is used from that point forth.  For example; if a plugin added a fixed, 32 byte header onto any packet it encrypted, then it should return `mtu - 32`.

Most encryption algorithms (e.g. AES) work on _blocks_.  A plugin should round down to the next block size, and then subtract the size of any header it expects to add to the packet.

#### Parameters

* **mtu** is the existing maximum transmission unit.

#### Return value

The modified MTU.

### ConnectionIdAssigned

```C
void ConnectionIdAssigned(
  int key_id,
  unsigned short connection_id);
```

This is called on the server, when a new connection has been accepted.

#### Parameters
* **key_id** The key identifier, which was written by the corresponding previous call to `Decrypt` for this packet.
* **connection_id** The connection id that will be used from this point forth.  In particular, as a parameter to subsequent `Encrypt` calls when sending packets back to the client.

### ConnectionDropped

```C
void ConnectionDropped(int connection_id);
```

This is called on the server and the client when a connection is dropped.

#### Parameters

* **connection_id** The identifier for this connection, as previously passed into `Encrypt`, `Decrypt` and (on the server) `ConnectionIdAssigned`.

## Example Plugin

On sending data, the plugin performs AES-256-CBC encryption on the data and then an SHA-256 HMAC on the entire packet, and places the HMAC value in a packet header.  A UUID that identifies the key is also written into the packet header.

On receiving data, the key UUID is used to find the HMAC and decryption keys.  The packet is first checked for corruption by repeating the HMAC locally, and then decrypted.

The example plugin has the concept of _KeySets_.  A KeySet consists of:
* A UUID identifier.
* A 256-bit key for AES encryption.
* A 16-byte initialization vector (IV) for AES encryption.
* A 256 bit key for the SHA-256 HMAC.

It is expected that there will be one KeySet _per connection_.  So for example a server hosting 32 clients would have 32 KeySets in memory at once.  It is expected that the keys are generated elsewhere (e.g. by a matchmaking server) and transmitted to the server and the client securely by some other means.

The example plugin provides the following functions to be called from the user's C# scripts, in addition to the mandatory ones described above.

### UnetEncryptionInit

Initializes the plugin.  Returns zero on success.  This must be called after `NetworkTransport.LoadEncryptionLibrary`, before any other function.

### SetLogFunc

```C
typedef void(*LogFunc) (const char * str);

void SetLogFunc(LogFunc f);
```

Sets a debug logging callback.  Callers should pass in a C# function taking a `string`.  This function will be called on errors with a description of the problem.

The error messages are intended for **you**, the developer calling the plugin's functions from your C# code.  They are not intended for consumption by the end-user (i.e. the player).

Bear in mind that this function will be called from the Unet thread.  Therefore you cannot call any Unity APIs from it.  See the example project for an approach where the messages are enqueued and then later serviced by the main thread.

### AddConnectionKeys

Adds a new KeySet.

```C
int AddConnectionKeys(
	const char * uuid_str,
	uint8_t * encryption_key,
	uint32_t encryption_key_length,
	uint8_t * hmac_key,
	uint32_t hmac_key_length,
	uint8_t * iv,
	uint32_t iv_length);
```

#### Parameters

* **uuid_str** The KeySet's UUID, in string form.  e.g. "d3508ba8-7c7c-44e0-8305-40b4cab55640".
* **encryption_key** The key to use for AES encryption.  C# code must pass this as a `byte []`.
* **encryption_key_length** The lenth of the **encryption_key** array.  This must be exactly 32.  From C# pass in _e.g._ key.Length rather than a hardcoded `32`, for safety's sake.
* **hmac_key** The key to use for SHA-256 HMAC.  C# code must pass this as a `byte []`.
* **hmac_key_length** The length of the **hmac_key** array.  This must be exactly 32.  From C# pass in _e.g._ hmac_key.Length rather than a hardcoded `32`, for safety's sake.
* **iv** The AES initialization vector.  C# code must pass this in as a `byte []`.
* **iv_length** The length of the IV.  As with the other `_length` parameters, this is provided as a safety check.

#### Return Value

Returns zero on success and nonzero on error.  On error, the KeySet will not have been added to the internal list.  The logging callback will be called with a description of the problem (e.g. duplicate UUID, incorrect length array, etc).

### RemoveConnectionKeys

```C
int RemoveConnectionKeys(const char * uuid_str);
```

Remove a previously-added KeySet.

#### Parameters

* **uuid_str** The KeySet UUID, as previously passed into `AddConnectionKeys`.

#### Return Value

Zero on success.  Nonzero on error (e.g. unparseable UUID).

### SetUuidForNextConnection

```C
int SetUuidForNextConnection(const char * uuid_str);
```

On the client, specifies the KeySet to use for the next call to `NetworkTransport.Connect`.

When `Encrypt` is called for a new connection, the `connection_id` will be a value that the plugin has not seen before.  Clients should call `SetUuidForNextConnection` to specify which KeySet to use in this situation.

The UUID of the KeySet is written into the packet, so the server will know which KeySet to use for decryption.

#### Parameters

* **uuid_str** The UUID of the KeySet to use.

#### Return Value

Zero on success.  Nonzero on error (e.g. unparseable UUID).



