from idaapi import BADADDR
import idaapi
import idautils
import ida_search

from .ida import IDA


def bad(ea):
    return ea == BADADDR


def find_probable_string_start(prologue, segment):
    string_addr = ida_search.find_binary(segment.end, segment.start, prologue, 16, ida_search.SEARCH_UP)
    if bad(string_addr):
        string_addr = 0
    return string_addr


def find_faddr_by_strref(string, start_address):
    function_address = BADADDR
    pk_ea = ida_search.find_text(start_address, 1, 1, string, ida_search.SEARCH_DOWN)

    if bad(pk_ea):
        return BADADDR

    if pk_ea < start_address:  # String is in func
        function_address = idaapi.get_func(pk_ea)

    for xref in idautils.XrefsTo(pk_ea):
        func = idaapi.get_func(xref.frm)
        if not func:
            continue
        function_address = func.start_ea

    if bad(pk_ea):
        return BADADDR

    return function_address
