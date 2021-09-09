
from disassembler_api.api import API, DisassemblerFile, Segment, Bitness, ProcessorType, SegmentType, SearchDirection
from .structs import StructLoader
from .maps import symbols


class SecureROMLoader:
    def __init__(self, api: API, fd, bitness, version_string):
        self.name = "SecureROM Loader"
        self.api: API = api
        self.file: DisassemblerFile = self.api.get_disasm_file(fd)
        self.bitness = bitness
        self.version_string = version_string

        self.segments = []
        self.code_segment: Segment = None
        self.ram_segment: Segment = None
        self.string_start = 0

    def load(self):
        self.configure_segments()

        print("[*] Defining entry point")
        self.api.add_entry_point(self.code_segment.start, "start")

        print("[*] Analyzing loaded code")
        self.api.analyze(self.code_segment.start, self.code_segment.end)

        print("[*] Finding string start")
        self.string_start = self.find_probable_string_start("6E 6F 72 30 00", self.code_segment)

        print("[*] Pass one")
        print("[*] Looking for function defs")
        self.find_stringref_funcs()

        if self.bitness != Bitness.Bitness32:
            print("[*] Looking for function from call graph")
            self.find_xrefs_from_start()

        self.check_symbol_map()

        print("[*] Loading custom struct types")
        StructLoader(self.api)

    def check_symbol_map(self):
        soc_name = self.version_string.split(',', 1)[0].split(' ')[-1]
        if soc_name in symbols['srom']:
            apply_symbols = self.api.ask(f'Symbols found from {symbols["srom"][soc_name]["credit"]}. Apply these symbols?')
            if apply_symbols:
                print("[*] Applying symbols...")
                for symbol in symbols["srom"][soc_name]["symbols"]:
                    print(f'  [+] {symbols["srom"][soc_name]["symbols"][symbol]} = {hex(symbol)}')
                    self.api.add_name(symbol, symbols["srom"][soc_name]["symbols"][symbol])

    def find_xrefs_from_start(self):
        for function_ea in self.api.function_addresses():
            # For each of the incoming references
            for ref_ea in self.api.xrefs_to(function_ea):
                # Get the name of the referring function
                caller_name = self.api.get_function_name(ref_ea)
                if caller_name == 'start':
                    print(f'  [+] _platform_start = {hex(function_ea)}')
                    self.api.add_name(function_ea, "_platform_start")
                    break

    def find_stringref_funcs(self):

        panic_location = self.find_faddr_by_strref("double panic in ", self.string_start)
        if not panic_location == self.api.bad_address():
            print(f'  [+] _panic = {hex(panic_location)}')
            self.api.add_name(panic_location, '_panic')

        task_location = self.find_faddr_by_strref("idle task", self.string_start)
        if not task_location == self.api.bad_address():
            print(f'  [+] _sys_setup_default_environment = {hex(task_location)}')
            self.api.add_name(task_location, '_sys_setup_default_environment')

    def configure_segments(self):
        base_addr = 0x0
        ptr_size = 0x8
        sram_len = 0x00120000

        if self.bitness == Bitness.Bitness32:
            self.api.set_processor_type(ProcessorType.ARM32)
            ptr_size = 0x4

        elif self.bitness == Bitness.Bitness64:
            self.api.set_processor_type(ProcessorType.ARM64)
            base_addr = 0x100000000

        sram_start_ptr = 0x300 + (7*ptr_size)

        self.code_segment = Segment("SecureROM", base_addr, self.file.size, SegmentType.CODE, self.bitness)
        self.api.create_segment(self.code_segment)

        sram_start = self.file.load_ptr_from(sram_start_ptr)

        self.ram_segment = Segment("SRAM", sram_start, sram_len, SegmentType.STACK, self.bitness)
        self.api.create_segment(self.ram_segment)
        self.api.add_name(sram_start_ptr + base_addr, "sram_start")

        self.segments.append(self.code_segment)

        self.api.copy_da_file_to_segment(self.file, self.code_segment, 0)

    def find_probable_string_start(self, prologue, segment):
        string_addr = self.api.search_binary(prologue, segment.end, segment.start, SearchDirection.UP)
        if string_addr == self.api.bad_address():
            string_addr = 0
        return string_addr

    def find_faddr_by_strref(self, string, start_address):
        function_address = self.api.bad_address()
        pk_ea = self.api.search_text(string, start_address, 0, SearchDirection.DOWN)

        if pk_ea == self.api.bad_address():
            return pk_ea

        if pk_ea < start_address:  # String is in func
            function_address = self.api.get_function(pk_ea)

        for xref in self.api.xrefs_to(pk_ea):
            func = self.api.get_function(xref.frm)
            if not func:
                continue
            function_address = func.start_ea

        if pk_ea == self.api.bad_address():
            return pk_ea

        return function_address
