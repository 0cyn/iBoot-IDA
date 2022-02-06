#
#  iBootLoader | ibootloader
#  loader.py
#
#  Base loader invoked by the respective disassembler's "Loader" script
#
#  This exists to abstract out everything possible to reduce the amount of changes
#  neeed to be made to the scripts in ./loaders specifically.
#
#  This file is part of iBootLoader. iBootLoader is free software that
#  is made available under the MIT license. Consult the
#  file "LICENSE" that is distributed together with this file
#  for the exact licensing terms.
#
#  Copyright (c) kat 2021.
#

from disassembler_api.api import Bitness, DisassemblerType
from disassembler_api.ida import IDAAPI

from .securerom import SecureROMLoader
from .iboot import IBootLoader
from .iboot_encrypted import IBootEncryptedLoader

def load_file(da_type, fd, neflags, format):

    print("[x] iBootLoader by kat")
    print("[x] initializing")
    if da_type == DisassemblerType.IDA:
        api = IDAAPI
    print(f'[+] Loaded disassembler module \'{api.api_name()}\'')

    # check if im4p
    IM4P_MAGIC = b'\x4D\x34\x50\x16'
    fd.seek(0x8)
    mag = fd.read(0x4)
    if mag == IM4P_MAGIC:
        if da_type == DisassemblerType.IDA:
            loader = IBootEncryptedLoader(api, fd, 0, "")
            loader.load()
    else:
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