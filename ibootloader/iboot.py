
from disassembler_api.api import API, DisassemblerFile, Segment, Bitness, ProcessorType, SegmentType, SearchDirection
from .structs import StructLoader
from .maps import symbols

class IBootLoader:
    def __init__(self, api: API, fd, bitness, version_string):
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

        print("[*] Looking for rebase address")
        rebase_addr = self.find_and_rebase()

        print("[*] Analyzing loaded code")
        self.api.analyze(rebase_addr, rebase_addr + self.code_segment.size)

    def find_and_rebase(self):
        rebase_ldr_addr = 0x44
        self.api.analyze(0x0, 0x100)
        rebase_addr = int(self.api.get_disasm(rebase_ldr_addr).split('=')[1], 16)

        print(f'  [+] {rebase_addr}')
        self.api.rebase_to(rebase_addr)
        return rebase_addr

    def configure_segments(self):

        base_addr = 0x0
        ptr_size = 0x8
        sram_len = 0x00120000

        if self.bitness == Bitness.Bitness32:
            self.api.set_processor_type(ProcessorType.ARM32)
            ptr_size = 0x4

        elif self.bitness == Bitness.Bitness64:
            self.api.set_processor_type(ProcessorType.ARM64)

        sram_start_ptr = 0x300 + (7*ptr_size)

        self.code_segment = Segment("iBoot", base_addr, self.file.size, SegmentType.CODE, self.bitness)
        self.api.create_segment(self.code_segment)

        self.segments.append(self.code_segment)

        self.api.copy_da_file_to_segment(self.file, self.code_segment, 0)

