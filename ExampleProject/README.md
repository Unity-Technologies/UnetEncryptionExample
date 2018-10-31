# ExampleProject

This project serves as an example of using the plugin.


## Instructions


### Plugin Compilation

Compile the plugin for each platform you wish to use.  For Windows, load and compile the `.sln`.  For Linux, run `make` in the `Plugins/Linux/OpenSSL`.  Place the compiled plugins (*.dll, *.so) in `Assets/Plugins`.  In the inspector, set each plugin to be usable from that platform only (e.g. Set the Linux .so file to be runnable from Linux only).


### Server

To run a server, simply "Build and Run".  Once the game starts running, click "Be the Server".

If you want to use a different port than the default 12345, alter the call to `NetworkTransport.AddHost` in `Server.cs`.

Take a note of the server's IP address, so that you can connect clients.



### Client

Edit the `Client` prefab, filling in the IP address and port of the server.

To run a client, select _Build and Run_ from the Build Settings window.  When the game runs, click _Be the client_.

On platforms without a mouse or touch input (e.g. consoles), the game will default to be a client after a short time.  See code in `Chooser.cs` and add your platform(s) as necessary.



### More than one Client

To have more than one client connect to the server using different keys, build the project again for each client and change the `Client Idx` field on the `Chooser` GameObject.  The number serves as an index into the `Keys` field underneath.  UUIDs are represented as strings in the usual manner, and key and IV data is represented as a base64-encoded string.

To generate more keys, execute the following commands on Linux or Cygwin:

* To create a new UUID:  `uuidgen`

* To create a 256-bit base64-encoded key:  `dd if=/dev/random bs=32 count=1 | base64`

* To create a 16-byte initialization vector:  `dd if=/dev/random bs=16 count=1 | base64`

These are just exmples.  Any random UUID will work, as will any base64-encoded series of 32 or 16 random bytes.


### Viewing Packets

The third-party tool Wireshark (https://www.wireshark.org/) is very useful for examining the packets as they appear "on the wire".  By specifying display filters it is possible to filter out just the Unet traffic.  For example on the default port 12345, use the display filter `(ip.proto == "udp") && (udp.port == 12345)`.
