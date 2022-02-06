# iBootLoader

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
python3 -m pip install --upgrade ilstrap
python3 -m ilstrap.installer --gh cxnder/iBootLoader
```


### What `ilstrap` does:

ilstrap is a little thing i threw together that creates a specific folder containing dependent modules located in `loaders/ilstrap/[Loader Name]`

aka, an **I**DA **L**oader boot**strap**er

it then injects a line of python into the front of `ida_bootloader.py` which adds that folder to the Path

that way, it can load any modules the loader depends on without requiring a package manager based setup process.

this metadata is included in the ilstrap.json file which ilstrap reads.

### Manual Installation

(if you dont want to use/dont trust [source is at https://github.com/cxnder/ilstrap] my lil installer framework, perfectly understandable)

Steps:

1. cd into your IDA directory (where ida64/ida64.exe is located)
2. Copy `ida_ibootloader.py` into `loaders/`
3. Copy the four folders located in `src/` to `loaders/`

---

###### Credits:

this project was originally inspired by https://github.com/argp/iBoot64helper

