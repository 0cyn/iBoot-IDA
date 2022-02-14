from typing import Union

from unicorn import *
from unicorn.arm64_const import *


class iEmulator:

    def __init__(self, fp, rom_size):
        self.fp = fp

        self.emu: Uc = Uc(UC_ARCH_ARM64, UC_MODE_ARM)  # pylance bitches if this isn't set. 
                                                       # it will get re-set by every emulator superclassing this.

        self.rom_base = 0
        self.rom_size = 0
        self.stack_base = 0
        self.stack_size = 0
        self.fp.seek(0)
        bytess = b''
        for i in range(rom_size // 0x20):
            self.fp.seek(i*0x20)
            bits = self.fp.read(0x20)
            bytess += bits 
        self.data = bytearray(bytess)
        self.bytes = bytes(self.data)

        self.skip_addrs = []
        
        self.emulator_hook_stop_point = 0x0

    def emulator_hook_all(self, uc, address, size, user_data):
        pass

    def emu_skip(self, address, instruction_size = 0x4):
        if self.emu:
            # TODO: maybe a better way to do this?
            #           couldn't find it in unicorn docs but didn't really look that hard.
            self.emu.reg_write(UC_ARM64_REG_PC, address + instruction_size)
    
    def read(self, location, size):
        return bytes(self.data[location:location+size])

    def read_int(self, location, size):
        return int.from_bytes(self.read(location, size), "little")

    def vm_read(self, location, size):
        return self.read(location - self.rom_base, size)

    def vm_read_int(self, location, size):
        return self.read_int(location - self.rom_base, size)

    def read_cstr_at(self, addr: int, limit: int = 0):

        ea = addr
        cnt = 0

        while True:
            try:
                if self.data[ea] != 0:
                    cnt += 1
                    ea += 1
                else:
                    break

            except IndexError as ex:
                raise ex

        text = self.read(addr, cnt).decode()

        return text

    def vm_read_cstr_at(self, location: int, limit: int = 0):
        self.read_cstr_at(self.rom_base + location, limit)