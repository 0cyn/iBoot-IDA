# ibootloader

WIP Loader for Apple's SecureROM/iBoot

---

this project was heavily inspired by https://github.com/argp/iBoot64helper

### why does this exist and why aren't you using [insert other project] instead?
  
None of the other projects properly support 32 bit, several are broken, and the code here is (only slightly) cleaner.


### Disassembler Support:

| Disassembler | Supported |
|--------------|-----------|
| IDA 7.0-7.5  | ✓         |
| Ghidra       | ✗         |
| Hopper       | ✗         |

# Filetype Support 

| File type                | Supported |
|--------------------------|-----------|
| arm32/64 SecureROM       | ✓         |
| arm32/64 iBoot/iBEC/iBSS | ✓         |
| SEPROM                   | ✗        |
