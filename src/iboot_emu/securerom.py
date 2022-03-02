from .emulator import *


class SecureROM_ARM64(iEmulator):
    def __init__(self, fp):
        super().__init__(fp, 0x20000)

        self.emu = Uc(UC_ARCH_ARM64, UC_MODE_ARM)

        self.pc_cache = {}

        self.rom_base = 0
        self.rom_size = 0x20000

        self.stack_base = 0
        self.stack_size = 2 * 1024 * 1024  # 20 mib; this isn't the real value, it just makes shit work

        self.symbols = {}

    def start(self):
        self.pre_setup()
        self.setup()

        self.emu.hook_add(UC_HOOK_CODE, self.emulator_hook_all, begin=self.rom_base, end=self.rom_base + self.rom_size)

    def launch(self, start, length):
        try:
            self.emu.emu_start(start, start + length)
        except UcError as ex:
            self.panic(ex)

    def panic(self, ex):
        PC = self.emu.reg_read(UC_ARM64_REG_PC)
        PANIC_STR = """
        Emulator (not the rom itself) Panicked with exception string: {}
        Program Counter: {}
        Thread State: 
        x0 = {}  |  x5 = {}  |  x10 = {}  | x15 = {}  |  x20 = {}
        x1 = {}  |  x6 = {}  |  x11 = {}  | x16 = {}  |  LR  = {}
        x2 = {}  |  x7 = {}  |  x12 = {}  | x17 = {}  | 
        x3 = {}  |  x8 = {}  |  x13 = {}  | x18 = {}  | 
        x4 = {}  |  x9 = {}  |  x14 = {}  | x19 = {}  |
        """.format(ex,
                   hex(PC),
                   hex(self.emu.reg_read(UC_ARM64_REG_X0)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X5)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X10)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X15)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X20)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X1)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X6)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X11)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X16)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X30)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X2)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X7)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X12)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X17)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X3)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X8)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X13)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X18)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X4)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X9)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X14)).ljust(13, ' '),
                   hex(self.emu.reg_read(UC_ARM64_REG_X19)).ljust(13, ' ')
                   )
        print(PANIC_STR)

    def resolve(self):
        self.platform_init()

    def platform_init(self):
        func_end = 0x0

        for i in range(0x200 // 0x4):
            dat = self.read(i * 0x4, 0x4)
            if dat == b'\x00\x00\x00\x00':
                func_end = (i * 0x4) - 0x4
                break

        func_end += self.rom_base
        self.emulator_hook_stop_point = func_end

        self.launch(self.rom_base, func_end)
        __main = self.emu.reg_read(UC_ARM64_REG_X30)
        self.symbols['__main'] = __main

    def emulator_hook_all(self, uc, address, size, user_data):
        super().emulator_hook_all(uc, address, size, user_data)

        if address not in self.pc_cache:
            self.pc_cache[address] = 0

        self.pc_cache[address] += 1

        inst = int.from_bytes(self.vm_read(address, size), "little")

        if self.pc_cache[address] < 5:
            # print(f'{hex(address)} == ' + hex(inst))
            pass

        if address in self.skip_addrs:
            self.emu_skip(address)

        # skipping msr/mrs instructions causes some infinite loops, 
        #   so we use this shit hack to avoid infinite recursion.
        #   the cap may need to be raised for certain copy loops.
        if self.pc_cache[address] > 1000:
            self.emu_skip(address)

        # we need to skip msr insts
        if inst & 0xFF000000 == 0xD5000000:
            self.emu_skip(address)

        if address == self.emulator_hook_stop_point:
            uc.emu_stop()

    def setup(self):
        self.emu.mem_map(self.rom_base, len(self.bytes))
        self.emu.mem_map(self.stack_base, self.stack_size)

        self.emu.mem_write(self.rom_base, self.bytes)

    def pre_setup(self):
        self.pre_setup_header()

    def pre_setup_header(self):
        """
        SecureROM (and iBoot iirc) encodes basic data about the rom starting from 0x200 
        """
        self.rom_base = self.read_int(0x318, 8)
        self.stack_base = self.read_int(0x338, 8)
