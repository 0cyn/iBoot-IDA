# iBoot-IDA

32/64 bit SecureROM/iBoot loader for IDA Pro. Supports IDA Pro 7.0+ on all platforms.

### Filetype Support

| File type                | Supported |
|--------------------------|-----------|
| arm32/64 SecureROM       | ✓         |
| arm32/64 iBoot/iBEC/iBSS | ✓         |
| Encrypted arm32/64 iBoot/iBEC/iBSS | ✓         |
| SEPROM                   | ✗        |

---

## Installation

```
python3 -m pip install --upgrade ilstrap unicorn
python3 -m ilstrap.installer --gh hack-different/iBoot-IDA
```

### Manual Installation

Steps:

0. Install unicorn using the same python installation your IDA install uses.
1. cd into your IDA directory (where ida64/ida64.exe is located)
2. Copy `plugins/ida_ibootplugin.py` into `plugins/`
3. Copy the folders in `plugin/src` into `plugins/`
4. Copy `loaders/ida_ibootloader.py` into `loaders/`
3. Copy the folders located in `loader/src/` to `loaders/`

---

###### Credits:

Maintainer: https://github.com/cxnder

AArch Sysregs plugin based on  https://github.com/TrungNguyen1909/aarch64-sysreg-ida (based on a plugin by bazad, based
on a script by someone else, based on ...)

this project was originally inspired by https://github.com/argp/iBoot64helper

