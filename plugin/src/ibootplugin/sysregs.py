'''
Copyright (c) 2022 ntrung03
This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
Based on https://gist.github.com/bazad/42054285391c6e0dcd0ede4b5f969ad2 by Brandon Azad
Based on https://gist.github.com/dougallj/7a75a3be1ec69ca550e7c36dc75e0d6f by Dougall J
'''

import idaapi
import ida_hexrays
import os
import json

from .sysregs_dat import *

ITYPE_MRS = idaapi.CUSTOM_INSN_ITYPE + 13
ITYPE_MSR = ITYPE_MRS + 1
ITYPE_SYS = ITYPE_MSR + 1

# AArch64 PSTATE accesses (op0 = 0b00, CRn = 0b0100).
PSTATE_ACCESS = {
    0b011 : 'UAO',
    0b100 : 'PAN',
    0b101 : 'SPSel',
    0b110 : 'DAIFSet',
    0b111 : 'DAIFClr',
}


def pstate_insn(op2):
    pstate = PSTATE_ACCESS.get(op2)
    if pstate:
        return pstate
    else:
        return ('#{:b}'.format(op2))

def sysreg_insn(op0, op1, CRn, CRm, op2):
    sr = 'S{}_{}_c{}_c{}_{}'.format(op0, op1, CRn, CRm, op2)
    #print(sr)
    reg = SYSTEM_REGISTERS.get(sr)
    if reg:
        name = reg[0]
        description = reg[1]
        return name
    else:
        return sr

def process_msr(insn):
    assert(insn & 0xFFC00000 == 0xD5000000)
    L   = (insn >> 21) &  0x1
    op0 = (insn >> 19) &  0x3
    op1 = (insn >> 16) &  0x7
    CRn = (insn >> 12) &  0xf
    CRm = (insn >>  8) &  0xf
    op2 = (insn >>  5) &  0x7
    Rt  = (insn >>  0) & 0x1f
    if L == 0b0 and op0 == 0b00 and CRn == 0b0100 and Rt == 0b11111:
        return pstate_insn(op2)
    elif op0 != 0b00:
        return sysreg_insn(op0, op1, CRn, CRm, op2)
    else:
        return '{:08x}'.format(insn)


class Aarch64SysRegHook(idaapi.IDP_Hooks):
    CUSTOM_INSTRUCTIONS = {idaapi.ARM_mrs, idaapi.ARM_msr, idaapi.ARM_sys}
    INDENT = 16

    def ev_out_operand(self, outctx, op):
        if outctx.insn.itype in self.CUSTOM_INSTRUCTIONS:
            insn = outctx.insn
            #print("ev_out_operand")
            if op.n < 2:
                if outctx.insn.itype == idaapi.ARM_mrs:
                    if op.n == 1:
                        outctx.out_colored_register_line(sysreg_insn(3, insn.ops[1].value, insn.ops[2].reg, insn.ops[3].reg, insn.ops[4].value))
                    else:
                        return 0
                elif outctx.insn.itype == idaapi.ARM_msr:
                    if op.n == 0:
                        outctx.out_colored_register_line(process_msr(idaapi.get_dword(outctx.insn.ea)))
                    else:
                        if insn.ops[2].type == idaapi.o_void:
                            return 0
                        else:
                            insn.itype = ITYPE_MSR
                            outctx.out_one_operand(4)
                            insn.itype = idaapi.ARM_msr
                elif outctx.insn.itype == idaapi.ARM_sys:
                    if op.n == 0:
                        outctx.out_colored_register_line(sysreg_insn(1, insn.ops[0].value, insn.ops[1].reg, insn.ops[2].reg, insn.ops[3].value).split()[1].strip())
                    else:
                        insn.itype = ITYPE_SYS
                        outctx.out_one_operand(4)
                        insn.itype = idaapi.ARM_sys
                '''
                for i in range(0, 6):
                    op = outctx.insn.ops[i]
                    print(F'Op{op.n}: type: {op.type} reg: {op.reg} value: {op.value}\n')
                '''
            return 1
        return 0
    def ev_out_mnem(self, outctx):
        if outctx.insn.itype == idaapi.ARM_sys:
            #print("ev_out_insn")
            insn = outctx.insn
            outctx.out_custom_mnem(sysreg_insn(1, insn.ops[0].value, insn.ops[1].reg, insn.ops[2].reg, insn.ops[3].value).split()[0].strip(), self.INDENT)
            return 1
        return 0

class Aarch64SysRegPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
    comment = "Aarch64 Apple SysReg extension"
    wanted_hotkey = ""
    help = "Runs transparently"
    wanted_name = "Aarch64 SysReg"
    hook = None
    enabled = 1

    def init(self):
        if idaapi.ph_get_id() != idaapi.PLFM_ARM or idaapi.BADADDR <= 0xFFFFFFFF:
            return idaapi.PLUGIN_SKIP
        if not ida_hexrays.init_hexrays_plugin():
            print(("[-] {0} : no decompiler available, skipping".format(self.wanted_name)))
            return idaapi.PLUGIN_SKIP
        print("%s init"%self.comment)

        d = json.loads(APPLE_REGS_JSON)

        for r in d:
            sr = 'S{}_{}_c{}_c{}_{}'.format(*r['enc'])
            SYSTEM_REGISTERS[sr] = (r['name'], r['fullname'])
        self.hook = Aarch64SysRegHook()
        self.hook.hook()
        return idaapi.PLUGIN_KEEP

    def run():
        pass

    def term(self):
        if self.hook is not None:
            self.hook.unhook()
        print("%s unloaded"%self.comment)

def PLUGIN_ENTRY():
    return Aarch64SysRegPlugin()