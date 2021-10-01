# ibootloader

### Installation

```
pip3 install --upgrade ilstrap

# On windows, run this in an administrator command prompt
python3 -m ilstrap.installer --gh KritantaDev/iBootLoader
```

---

### Disassembler Support:

| Disassembler | Supported |
|--------------|-----------|
| IDA 7.0-7.6  | ✓         |

# Filetype Support 

| File type                | Supported |
|--------------------------|-----------|
| arm32/64 SecureROM       | ✓         |
| arm32/64 iBoot/iBEC/iBSS | ✓         |
| Encrypted arm32/64 iBoot/iBEC/iBSS | ✓         |
| SEPROM                   | ✗        |



---

this project was heavily inspired by https://github.com/argp/iBoot64helper

### why does this exist and why aren't you using [insert other project] instead?
  
None of the other projects properly support 32 bit, several are broken, and the code here is (only slightly) cleaner.
