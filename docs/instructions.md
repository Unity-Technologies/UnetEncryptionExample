# Instructions


To tell the Unity build to use your plugin, call `UnityEngine.Networking.NetworkTransport.LoadEncryptionLibrary(path)` where `path` is the path to your compiled plugin. Typically on Windows it will be `string.Format("{0}/Plugins/UnetEncryption.dll", Application.dataPath)`.


In this call, Unity will check that the file exists and that it provides the mandatory functions (listed [here](functions.md)) all exist.  These are the functions that the runtime itself will call. If you are creating your own plugin then you will almost certainly need to add more functions that you will call from C# code, _e.g._ to provide the plugin with key values. Do this in the usual way for native plugins callable from C#.

Bear in mind that the location of a plugin in the _built_ version of your game is not necessarily the same as in your `Assets` folder.

The source for the reference plugin (including the document you are reading now) is available from https://github.com/Unity-Technologies/UnetEncryptionExample.  It performs AES-CBC-256 encryption and SHA-256 HMAC. The file `Plugins/Shared/Packet.h` shows the structure of the transmitted packet. You can view the packets in a tool such as Wireshark. The Linux version was developed and tested on Ubuntu 16.04 LTS, and the Windows version on Windows 10.

Please study the plugin source to familiarize yourselves with what it does. It is meant as a starting point rather than a drop-in solution.

To use the reference plugin, call `UnetEncryptionInit` after calling `NetworkTransport.LoadEncryptionLibrary`. Then call `AddConnectionKeys` for each connection key-set, passing in the keys as a `byte[]` and the UUID as a `string` (without Microsoft-style `{` and `}`. _e.g._ `"626dc485-e1b1-42f4-9ff7-02378326080b"`). To avoid leaking memory, call `RemoveConnectionKeys` when keys are no longer required.

On the client, call `SetUuidForNextConnection` before connecting, passing in the UUID (as a string) of the key set to use.

You can optionally call `SetLogFunc`, passing in a C# callback function that receives a string. The callback will be fired on error conditions, which can be useful for debugging. On non-error conditions, the plugin is silent. Do not enable the callback in release builds, otherwise attackers could launch a denial-of-service attack on your server, by sending junk packets and causing extreme amounts of logging to the player log.
