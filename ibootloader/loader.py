
from disassembler_api.api import Bitness, DisassemblerType
from disassembler_api.ida import IDAAPI

from .securerom import SecureROMLoader
from .iboot import IBootLoader

def load_file(da_type, fd, neflags, format):

    print("[x] iBootLoader by kat")
    print("[x] initializing")
    if da_type == DisassemblerType.IDA:
        api = IDAAPI
    print(f'[+] Loaded disassembler module \'{api.api_name()}\'')

    fd.seek(0x0)
    bn = fd.read(0x4)
    fd.seek(0x200)
    ver_bin = fd.read(0x30)

    bitness = Bitness.Bitness32 if b'\xea' in bn else Bitness.Bitness64
    ver_str = ver_bin.decode()
    ver_str = "%s" % (ver_str)
    if ver_str[:9] == "SecureROM":
        if da_type == DisassemblerType.IDA:
            loader = SecureROMLoader(api, fd, bitness, ver_str)

    if ver_str[:5] == "iBoot":
        if da_type == DisassemblerType.IDA:
            loader = IBootLoader(api, fd, bitness, ver_str)

    print(f'[+] Using loader module \'{loader.name}\'')

    loader.load()