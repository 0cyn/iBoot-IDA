
from disassembler_api.api import Bitness, DisassemblerType
from disassembler_api.ida import IDAAPI

from .securerom import SecureROMLoader

def load_file(da_type, fd, neflags, format):

    print("[x] iBootLoader for IDA 7.5+ by kat")
    print("[x] initializing")

    fd.seek(0x0)
    bn = fd.read(0x4)
    fd.seek(0x200)
    ver_bin = fd.read(0x30)

    bitness = Bitness.Bitness32 if b'\xea' in bn else Bitness.Bitness64
    ver_str = ver_bin.decode()
    ver_str = "%s" % (ver_str)
    if ver_str[:9] == "SecureROM":
        if da_type == DisassemblerType.IDA:
            loader = SecureROMLoader(IDAAPI, fd, bitness, ver_str)
            loader.load()
