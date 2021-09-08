"""
A lot of this abstraction is to just make things more clear
IDA's API sucks and has zero docstrings or variable names to make things easier :p
"""
import ida_kernwin
import idautils

from .api import Bitness, ProcessorType, API, DisassemblerFile, Segment, SearchDirection

import ida_auto
import ida_segment
import ida_struct
import ida_entry
import idc_bc695
import ida_funcs
import ida_name
import ida_search
import idaapi
import idc


class IDAAPI(API):

    @staticmethod
    def get_function(location):
        idaapi.get_func(location)

    @staticmethod
    def bad_address():
        return idaapi.BADADDR

    @staticmethod
    def search_text(text, start, end, direction):
        direc = ida_search.SEARCH_UP if direction == SearchDirection.UP else ida_search.SEARCH_DOWN
        return ida_search.find_text(start, 1, 1, text, direc)

    @staticmethod
    def search_binary(binary, start, end, direction):
        direc = ida_search.SEARCH_UP if direction == SearchDirection.UP else ida_search.SEARCH_DOWN
        return ida_search.find_binary(start, end, binary, 16, direc)

    @staticmethod
    def get_disasm_file(fd):
        return IDAFile(fd)

    @staticmethod
    def create_segment(segment: Segment):

        segm = idaapi.segment_t()
        segm.bitness = segment.seg_bitness
        segm.start_ea = segment.start
        segm.end_ea = segment.end

        segm_type = segment.seg_type.name.upper()

        idaapi.add_segm_ex(segm, segment.name, segm_type, idaapi.ADDSEG_OR_DIE)

    @staticmethod
    def copy_da_file_to_segment(file, segment, file_location):
        file.fd.file2base(file_location, segment.start, segment.end, False)

    @staticmethod
    def add_entry_point(location: int, name: str) -> None:
        ida_entry.add_entry(0, location, name, True, 0)

    @staticmethod
    def set_processor_type(type):
        if type == ProcessorType.ARM32:
            idaapi.set_processor_type('ARM:ARMv7-A', idaapi.SETPROC_LOADER_NON_FATAL)
            idaapi.get_inf_structure().lflags |= idaapi.LFLG_PC_FLAT
        elif type == ProcessorType.ARM64:
            idaapi.set_processor_type("arm", idaapi.SETPROC_LOADER_NON_FATAL)
            idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT

    @staticmethod
    def function_addresses():
        return idautils.Functions()

    @staticmethod
    def xrefs_to(function_ea):
        return idautils.CodeRefsTo(function_ea, 0)

    @staticmethod
    def get_function_name(location):
        return idc.get_func_name(location)

    @staticmethod
    def add_struct(struct):
        struct_id = idc.add_struc(0, struct.name, 0)
        for field in struct.fields:
           idc.add_struc_member(struct_id, field.name, -1, field.ftype, -1, field.nbytes)

    @staticmethod
    def add_entry(location, name, code=True, flags=0):
        ida_entry.add_entry(0, location, name, code, flags)

    @staticmethod
    def add_name(location, name, flags=0):
        ida_name.set_name(location, name, flags)

    @staticmethod
    def ask(text):
        return ida_kernwin.ask_yn(0, text) == 1

    @staticmethod
    def analyze(start, end):
        ida_auto.plan_and_wait(start, end, True)


class IDAFile(DisassemblerFile):
    def __init__(self, fd):
        self.fd = fd

        fd.seek(0x0)
        bn = fd.read(0x4)
        self.bitness = Bitness.Bitness32 if b'\xea' in bn else Bitness.Bitness64
        fd.seek(0)
        fd.seek(0, idaapi.SEEK_END)
        size = fd.tell()
        fd.seek(0)
        self.size = size

    def load_ptr_from(self, location):
        self.fd.seek(location)
        ptr_size = 0x4 if self.bitness == Bitness.Bitness32 else 0x8
        ptr = self.fd.read(ptr_size)
        self.fd.seek(0)
        return int.from_bytes(ptr, "little")

