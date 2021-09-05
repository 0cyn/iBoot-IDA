"""
A lot of this abstraction is to just make things more clear
IDA's API sucks and has zero docstrings or variable names to make things easier :p
"""

from enum import IntEnum

import ida_auto
import ida_segment
import ida_entry
import idc_bc695
import ida_funcs
import ida_name
import ida_search
import idaapi


class Bitness(IntEnum):
    Bitness32 = 1
    Bitness64 = 2


class IDA:
    @staticmethod
    def add_entry(location, name, code=True, flags=0):
        ida_entry.add_entry(0, location, name, code, flags)

    @staticmethod
    def add_name(location, name, flags=0):
        ida_name.set_name(location, name, flags)

    @staticmethod
    def analyze(start, end):
        ida_auto.plan_and_wait(start, end, True)


class IDAFile:
    def __init__(self, fd):
        self.fd = fd
        fd.seek(0, idaapi.SEEK_END)
        size = fd.tell()
        fd.seek(0)
        self.size = size

    def copy_into_segment(self, file_location, segment):
        self.fd.file2base(file_location, segment.start, segment.end, False)


class Segment:
    def __init__(self, name, start, size, segm_type="CODE", bitness=Bitness.Bitness64):

        self.start = start
        self.end = start + size

        self.segm = idaapi.segment_t()
        self.segm.bitness = bitness
        self.segm.start_ea = self.start
        self.segm.end_ea = self.end

        idaapi.add_segm_ex(self.segm, name, segm_type, idaapi.ADDSEG_OR_DIE)