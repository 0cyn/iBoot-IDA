import idaapi
import idautils
import idc
import ida_kernwin

from .ida import IDA, IDAFile, Segment, Bitness
from .util import find_faddr_by_strref, bad, find_probable_string_start
from .maps import symbols


class SecureROMLoader:
    def __init__(self, fd, bitness, version_string):
        self.file = IDAFile(fd)
        self.bitness = bitness
        self.version_string = version_string

        self.segments = []
        self.code_segment: Segment = None
        self.string_start = 0

    def analyze(self, segment):
        IDA.analyze(segment.start, segment.end)

    def load(self):
        self.configure_segments()

        print("[*] Defining entry point")
        IDA.add_entry(self.code_segment.start, "start", True, 0)

        print("[*] Analyzing loaded code")
        self.analyze(self.code_segment)

        print("[*] Finding string start")
        self.string_start = find_probable_string_start("6E 6F 72 30 00", self.code_segment)

        print("[*] Pass one")
        print("[*] Looking for function defs")
        self.find_stringref_funcs()

        if self.bitness != Bitness.Bitness32:
            print("[*] Looking for function from call graph")
            self.find_xrefs_from_start()

        self.check_symbol_map()

    def check_symbol_map(self):
        soc_name = self.version_string.split(',', 1)[0].split(' ')[-1]
        if soc_name in symbols['srom']:
            apply_symbols = ida_kernwin.ask_yn(0, f'Symbols found from {symbols["srom"][soc_name]["credit"]}. Apply these symbols?')
            # print(apply_symbols)
            if apply_symbols == 1:
                print("[*] Applying symbols...")
                for symbol in symbols["srom"][soc_name]["symbols"]:
                    print(f'  [+] {symbols["srom"][soc_name]["symbols"][symbol]} = {hex(symbol)}')
                    IDA.add_name(symbol, symbols["srom"][soc_name]["symbols"][symbol])

    def find_xrefs_from_start(self):
        for function_ea in idautils.Functions():
            # For each of the incoming references
            for ref_ea in idautils.CodeRefsTo(function_ea, 0):
                # Get the name of the referring function
                caller_name = idc.get_func_name(ref_ea)
                if caller_name == 'start':
                    print(f'  [+] _platform_start = {hex(function_ea)}')
                    IDA.add_name(function_ea, "_platform_start")
                    break

    def find_stringref_funcs(self):

        panic_location = find_faddr_by_strref("double panic in ", self.string_start)
        if not bad(panic_location):
            print(f'  [+] _panic = {hex(panic_location)}')
            IDA.add_name(panic_location, '_panic')

        task_location = find_faddr_by_strref("idle task", self.string_start)
        if not bad(task_location):
            print(f'  [+] _sys_setup_default_environment = {hex(task_location)}')
            IDA.add_name(task_location, '_sys_setup_default_environment')

    def configure_segments(self):
        base_addr = 0x0

        if self.bitness == Bitness.Bitness32:
            idaapi.set_processor_type('ARM:ARMv7-A', idaapi.SETPROC_LOADER_NON_FATAL)
            idaapi.get_inf_structure().lflags |= idaapi.LFLG_PC_FLAT

        elif self.bitness == Bitness.Bitness64:
            idaapi.set_processor_type("arm", idaapi.SETPROC_LOADER_NON_FATAL)
            idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT
            base_addr = 0x100000000

        self.code_segment = Segment("SecureROM", base_addr, self.file.size, "CODE", self.bitness)
        self.segments.append(self.code_segment)

        self.file.copy_into_segment(0, self.code_segment)
