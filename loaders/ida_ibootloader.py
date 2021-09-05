
from ibootloader import loader
import sys

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
        bn = fd.read(0x4)
        fd.seek(0x200)
        ver_bin = fd.read(0x30)
        ver_str = ""

        bitness = 'AArch32' if b'\xea' in bn else 'AArch64'

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


def load_file(fd, neflags, format):
    loader.load_file(fd, neflags, format)

    return 1

# EOF
