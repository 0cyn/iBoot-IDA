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
python3 -m ilstrap.installer --gh hack-different/iBoot-IDA
```

### Manual Installation

Steps:

1. cd into your IDA directory (where ida64/ida64.exe is located)
2. Copy `ida_ibootloader.py` into `loaders/`
3. Copy the four folders located in `src/` to `loaders/`

---

###### Credits:

this project was originally inspired by https://github.com/argp/iBoot64helper

