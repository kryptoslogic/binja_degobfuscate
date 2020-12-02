# DeGObfuscate (v1.0.0)
Author: **Jamie Hankins**

_De-obfuscates strings inside of obfuscated Go binaries_

## Description:

This plugin implements a simple LLIL emulator to statically de-obfuscate simple string obfuscation such as the obfuscations done by [gobfuscate](https://github.com/unixpickle/gobfuscate).

To activate it, use either the `Tools` menu or the command palette. It offers two modes, the first will attempt to analyze the current function while the other will attempt to find all functions that are merely obfuscated strings and rename them. If the function name cannot be cleanly replaced, a comment will be added at all call locations with the detailed deobfuscated string in addition to the truncated rename.

![](https://github.com/jamie-34254/binja_degobfuscate/blob/master/img/DeGObfuscate.gif?raw=true)


## Installation Instructions

### Darwin

no special instructions, package manager is recommended

### Windows

no special instructions, package manager is recommended

### Linux

no special instructions, package manager is recommended

## Minimum Version

This plugin requires the following minimum version of Binary Ninja:

* 1528


## License

This plugin is released under a MIT license.
## Metadata Version

2
