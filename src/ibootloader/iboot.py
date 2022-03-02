#
#  iBootLoader | ibootloader
#  iboot.py
#
#  Loader for a decrypted Full iBoot file
#
#  This file is part of iBootLoader. iBootLoader is free software that
#  is made available under the MIT license. Consult the
#  file "LICENSE" that is distributed together with this file
#  for the exact licensing terms.
#
#  Copyright (c) kat 2021.
#

from disassembler_api.api import API, DisassemblerFile, Segment, Bitness, ProcessorType, SegmentType, SearchDirection


class IBootLoader:
    def __init__(self, api: API, fd, bitness, version_string):
        self.name = "iBoot Loader"
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
        siz = self.code_segment.size
        self.code_segment.start = rebase_addr
        self.code_segment.end = rebase_addr + siz

        print("[*] Analyzing loaded code")
        self.api.analyze(rebase_addr, rebase_addr + self.code_segment.size)

        print("[*] Looking for string start")
        self.string_start = self.find_probable_string_start("darwinos-ramdisk", self.code_segment)
        if self.string_start == 0:
            print("  [-] Did not find.")

        print("[*] Looking for symbols")
        self.find_strref_syms()

    def find_strref_syms(self):
        panic_location = self.find_faddr_by_strref("double panic in ", self.string_start, -1)
        print(f'{panic_location}')
        if not panic_location == self.api.bad_address():
            print(f'  [+] _panic = {hex(panic_location)}')
            self.api.add_name(panic_location, '_panic')

    def find_probable_string_start(self, prologue, segment):
        string_addr = self.api.search_text(prologue, segment.end, segment.start, SearchDirection.UP)
        if string_addr == self.api.bad_address():
            string_addr = 0
        return string_addr

    def find_and_rebase(self):
        rebase_ldr_addr = 0x44
        if self.bitness == Bitness.Bitness64:
            rebase_ldr_addr = 0x8
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

        sram_start_ptr = 0x300 + (7 * ptr_size)

        self.code_segment = Segment("iBoot", base_addr, self.file.size, SegmentType.CODE, self.bitness)
        self.api.create_segment(self.code_segment)

        self.segments.append(self.code_segment)

        self.api.copy_da_file_to_segment(self.file, self.code_segment, 0)

    def find_faddr_by_strref(self, string, start_address, off):
        function_address = self.api.bad_address()
        pk_ea = self.api.search_text(string, start_address, 0, SearchDirection.DOWN)

        if pk_ea == self.api.bad_address():
            print(f'  [-] {string} not found')
            return pk_ea

        if pk_ea < start_address:  # String is in func
            function_address = self.api.get_function(pk_ea)

        if len([i for i in self.api.xrefs_to(pk_ea)]) == 0:
            print(f'  [-] no xrefs to {hex(pk_ea)} found')

        # print([i for i in self.api.xrefs_to(pk_ea)])

        for xref in self.api.xrefs_to(pk_ea):
            func = self.api.get_function(xref.frm)
            if not func:
                # print(f'Bad Function {hex(xref.frm)}')
                continue
            function_address = func.start_ea
            if function_address == self.api.bad_address():
                print(f'  [-] {hex(xref)} func not found')
            break

        return function_address
