# UnetEncryptionPlugin

This repository contains a reference implementation of a Unet encryption plugin, as well as a very small example Unity project that uses the plugin.

The following documentation pages exist:

* [Functions](docs/functions.md) lists the functions that any encryption plugin must provide, as well as the extra functions provided by the example plugin.

* [Example Project](ExampleProject/README.md) has instructions for running the example project that uses the plugin.

* [Detection and Processing of Duplicate Packets](docs/duplication.md) describes that step that UNet takes (even when unencrypted) to defend against replay attacks.
