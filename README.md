# UnetEncryptionPlugin

Unity versions **2018.4** (from 2018.4.16) and **2019.3** (from 2019.3.0a6) can be configured to use **UNet encryption plugins**.  These are native plugins, provided by the user, that can be used to encrypt (or otherwise modify) the contents of a network packet sent or received by UNet.  The plugin is the very *last* thing to be run before packet *transmission*, and the very *first* thing to be run on packet *receipt*.  This allows the user to implement packet encryption, as required by certain console platforms.

The user is free to design their own encryption plugin as they see fit.  However this repository contains a **reference implementation** of a plugin that performs AES encryption, as well as a very small example Unity project that uses that plugin.

The following documentation pages exist:

* [Instructions](docs/instructions.md) shows to to tell Unity to use _any_ encryption plugin, as well as instructions specific to the example plugin.

* [Functions](docs/functions.md) lists the functions that any encryption plugin must provide, as well as the extra functions provided by the example plugin.

* [Example Project](ExampleProject/README.md) has instructions for running the example project that uses the plugin.

* [Detection and Processing of Duplicate Packets](docs/duplication.md) describes that step that UNet takes (even when unencrypted) to defend against replay attacks.
