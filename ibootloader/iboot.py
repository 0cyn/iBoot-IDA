
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

        print("[*] Analyzing loaded code")
        self.api.analyze(self.code_segment.start, self.code_segment.end)

    def configure_segments(self):

        base_addr = 0x48818000
        ptr_size = 0x8
        sram_len = 0x00120000

        if self.bitness == Bitness.Bitness32:
            self.api.set_processor_type(ProcessorType.ARM32)
            ptr_size = 0x4

        elif self.bitness == Bitness.Bitness64:
            self.api.set_processor_type(ProcessorType.ARM64)
            base_addr = 0x100000000

        sram_start_ptr = 0x300 + (7*ptr_size)

        self.code_segment = Segment("iBoot", base_addr, self.file.size, SegmentType.CODE, self.bitness)
        self.api.create_segment(self.code_segment)

        self.segments.append(self.code_segment)

        self.api.copy_da_file_to_segment(self.file, self.code_segment, 0)

