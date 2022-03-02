#
#  iBootLoader | loaders
#  ida_ibootloader.py
#
#  This is the loader script for IDA Pro 7.5
#
#  This file is part of iBootLoader. iBootLoader is free software that
#  is made available under the MIT license. Consult the
#  file "LICENSE" that is distributed together with this file
#  for the exact licensing terms.
#
#  Copyright (c) kat 2021.
#

import sys

import idaapi

from disassembler_api.api import DisassemblerType
from ibootloader import loader, cache

DEBUG_WITHIN_IDA = 0


def dprint(string):
    if DEBUG_WITHIN_IDA or len(sys.argv) > 1:
        # Launching the script manually with args will trigger debug prints
        __builtins__.print(string)


print = dprint


def accept_file(fd, fname):
    flag = 0
    # version = 0
    ret = 0

    if type(fname) == str:
        fd.seek(0x0)

        # check if im4p
        IM4P_MAGIC = b'\x4D\x34\x50\x16'
        fd.seek(0x8)
        mag = fd.read(0x4)
        if mag == IM4P_MAGIC:
            ret = {
                "format": f'iBootLoader: iBoot (Encrypted)',
                "processor": "arm"
            }
            return ret

        fd.seek(0x0)

        bn = fd.read(0x4)
        fd.seek(0x200)
        ver_bin = fd.read(0x30)
        ver_str = ""

        bitness = 'AArch32' if b'\xea' in bn else 'AArch64'
        cache.Cache().update_latest_filename(fname)

        try:
            ver_str = ver_bin.decode()
            ver_str = "%s" % (ver_str)
        except:
            print("Exception on SecureRom")
        if ver_str[:9] == "SecureROM":
            ret = {
                "format": f'iBootLoader: SecureROM ({bitness})',
                "processor": "arm"
            }
            flag = 1

            return ret

        if ver_str[:9] == "AVPBooter":
            ret = {
                "format": f'iBootLoader: VMApple SecureROM ({bitness})',
                "processor": "arm"
            }
            flag = 1

            return ret

        fd.seek(0x280)
        ver_bin = fd.read(0x20)

        try:
            ver_str = ver_bin.decode()
            ver_str = "%s" % (ver_str)
        except:
            print("Exception on iBoot")

        if ver_str[:5] == "iBoot":
            version = ver_str[6:]  # for later
            ret = {
                "format": f'iBootLoader: iBoot ({bitness})',
                "processor": "arm"
            }
            flag = 2

            return ret

        # TODO: SEPROM
        return 0
        fd.seek(0x800)
        ver_bin = fd.read(0x16)
        print(ver_bin)
        try:
            ver_str = ver_bin.decode()
            ver_str = "%s" % (ver_str)
        except:
            print("Exception on SEPROM")
        if ver_str[:11] == "iBootLoader: AppleSEPROM":
            version = ver_str[12:]
            ret = {
                "format": "SEPROM (AArch32)",
                "processor": "arm"
            }
            flag = 3

            return ret

    return ret


def load_file(file_descriptor, neflags, format):
    loader.load_file(DisassemblerType.IDA, file_descriptor, neflags, format)

    return 1


# noinspection PyPep8Naming
def PLUGIN_ENTRY():
    class iBootLoaderPlugin(idaapi.plugin_t):
        flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
        comment = "Aarch64 Apple SecureROM loader plugin"
        help = "Runs transparently"
        wanted_name = "Aarch64 SecureROM Loader"
        wanted_hotkey = str()
        hook = None

        def init(self):
            pass

        def run(self, arg):
            pass

        def term(self):
            pass

    return iBootLoaderPlugin()
