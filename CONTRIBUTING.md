# Contribution Info & Guidelines

Contributions are always welcome! 

You're free to hop right in if you have some features or fixes you want to implement; don't sweat about code guidelines too much. 

This document is mainly here to outline the basic layout and architecture of this project, to make your life easier.

## IStrap

iStrap is an installation framework for IDA Plugins + Loaders. This project uses it for quick installation, and conforms to a layout for it defined in ./istrap.json, which also contains basic project info.

## Project Structure

This project contains both a plugin, and a loader.

`loader/` - Contains the IDA Loader and python source modules.

`plugin/` - Contains the IDA Plugin and python source modules.

`istrap.json` - Contains project layout for the installer and basic info about the project. 

### Loader

`loader/ida_ibootloader.py` - This is the file that IDA will see as the "Loader". It's the 'face' IDA sees for our loader. Any actual code is in our modules below, and iStrap handles making sure our imports work.

#### Modules: 

All of these are located in `loader/src`

`ibootloader/` - Main Module. Contains the 'important' code for loading SecureROM/iBoot/etc.

`disassembler_api/` - This is an abstraction of the IDA API. It will in the future be expanded to abstract other disassemblers as well. 

`iboot_emu/` - iBoot/SROM Emulation code dependent on unicorn. Used currently for some symbol resolution. 

`kimg4` - Static clone of the `kimg4` pypi module, used here for decrypting encrypted iboot im4ps

`pyaes` - AES Decryption dependency of `kimg4`

### Plugin

// Currently, the plugin just implements sysreg labeling code. It will be expanded in the future to do more cool and awesome things.

`plugin/ida_ibootplugin.py` - Face of the plugin, actual plugin code is located in modules. 

#### Modules

All located in `plugin/src`

`ibootplugin` - Main Module 
