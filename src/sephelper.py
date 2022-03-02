import enum

import idaapi
import idc

IDA_REJECT_FILE = 0


class IDASegmentType(enum.Enum):
    Segment32 = 1
    Segment64 = 2

    @staticmethod
    def from_bits(bits: int) -> "IDASegmentType":
        if bits == 32:
            return IDASegmentType.Segment32
        elif bits == 64:
            return IDASegmentType.Segment64

        raise TypeError


PROLOGUES = {
    IDASegmentType.Segment32: ["03 AF", "02 AF", "01 AF"],
    IDASegmentType.Segment64: ["BF A9", "BD A9"]
}

FORMATS = {
    "SEPROM (AArch32)": {
        "processor": "arm",
        "bits": 32,
        "base_addr": 0x10000000
    },
    "SEPROM (AArch64)": {
        "format": "SEPROM (AArch64)",
        "processor": "arm",
        "bits": 64,
        "base_addr": 0x240000000,
    }
}


def func64(base_ea, base_end_ea, name, sequence):
    seq_ea = idaapi.find_binary(base_ea, base_end_ea, sequence, 0x10, idaapi.SEARCH_DOWN)

    if seq_ea != idaapi.BADADDR:
        func = idaapi.get_func(seq_ea)
        if func is not None:
            print("  [sephelper]: %s = 0x%x" % (name, func.start_ea))
            idc.set_name(func.start_ea, name, idc.SN_CHECK)
            return func.start_ea

    print("  [sephelper]: %s = NULL" % name)
    return idaapi.BADADDR


# Registers.
# https://siguza.github.io/APRR/
# https://gist.github.com/bazad/42054285391c6e0dcd0ede4b5f969ad2

def find_function(seg_start, seg_end):
    func64(seg_start, seg_end, "_DEROidCompare", "a1 01 00 b4  02 05 40 f9")
    func64(seg_start, seg_end, "_DERImg4Decode", "61 03 00 54  88 26 40 a9")
    func64(seg_start, seg_end, "_DERParseBoolean", "08 01 40 39  1f fd 03 71")
    func64(seg_start, seg_end, "_DERParseInteger", "00 01 00 35  e8 07 40 f9")
    func64(seg_start, seg_end, "_DERParseSequence", "e0 01 00 35  e8 07 40 f9")
    func64(seg_start, seg_end, "_DERDecodeSeqNext", "e8 03 00 f9  28 01 08 cb")
    func64(seg_start, seg_end, "_DERParseInteger64", "0b 15 40 38  4b dd 78 b3")
    func64(seg_start, seg_end, "_DERParseBitString", "08 00 80 d2  5f 00 00 39")
    func64(seg_start, seg_end, "_DERImg4DecodePayload", "33 03 00 b4  09 01 40 f9")
    func64(seg_start, seg_end, "_DERImg4DecodeProperty", "e8 07 40 b9  08 09 43 b2")
    func64(seg_start, seg_end, "_DERParseSequenceContent", "ec 03 8c 1a  2d 69 bc 9b")
    func64(seg_start, seg_end, "_DERDecodeSeqContentInit", "09 04 40 f9  08 01 09 8b")
    func64(seg_start, seg_end, "_DERImg4DecodeTagCompare", "f3 03 01 aa  08 04 40 f9")
    func64(seg_start, seg_end, "_DERImg4DecodeRestoreInfo", "a1 29 a9 52  41 8a 86 72")
    func64(seg_start, seg_end, "_DERImg4DecodeFindProperty", "00 00 80 52  a8 0a 43 b2")
    func64(seg_start, seg_end, "_DERImg4DecodeFindInSequence", "60 02 80 3d  fd 7b 44 a9")
    func64(seg_start, seg_end, "_DERDecodeItemPartialBufferGetLength", "09 04 40 f9  3f 09 00 f1")
    func64(seg_start, seg_end, "_DERImg4DecodeParseManifestProperties", "80 02 80 3d  a1 3a 00 91")

    func64(seg_start, seg_end, "_Img4DecodeEvaluateDictionaryProperties", "e0 03 1f 32  0a fd 7e d3")
    func64(seg_start, seg_end, "_Img4DecodeGetPropertyBoolean", "21 08 43 b2  e0 03 00 91")
    func64(seg_start, seg_end, "_Img4DecodeCopyPayloadDigest", "?? ?? 02 91  e0 03 15 aa")
    func64(seg_start, seg_end, "_Img4DecodeGetPropertyData", "00 00 80 52  e8 17 40 f9")
    func64(seg_start, seg_end, "_Img4DecodeGetPayload", "00 81 c9 3c  20 00 80 3d")
    func64(seg_start, seg_end, "_Img4DecodeInit", "20 01 00 35  c0 c2 00 91")

    func64(seg_start, seg_end, "_ccn_n", "63 04 00 91  5f 00 00 f1")
    func64(seg_start, seg_end, "_ccn_cmp", "7f 00 05 eb  c0 80 80 9a")
    func64(seg_start, seg_end, "_ccn_sub", "84 00 04 eb  40 00 00 b5")
    func64(seg_start, seg_end, "_ccn_add", "84 00 00 b1  40 00 00 b5")
    func64(seg_start, seg_end, "_cc_muxp", "08 c1 20 cb  28 00 08 8a")
    func64(seg_start, seg_end, "_cchmac_init", "69 22 00 91  8a 0b 80 52")
    func64(seg_start, seg_end, "_ccdigest_init", "f4 03 00 aa  60 22 00 91")
    func64(seg_start, seg_end, "_ccdigest_update", "e1 00 00 54  81 fe 46 d3")

    func64(seg_start, seg_end, "_verify_chain_signatures", "?? 09 00 b4  68 12 40 f9")
    func64(seg_start, seg_end, "_read_counter_py_reg_el0", "20 e0 3b d5")
    func64(seg_start, seg_end, "_write_ktrr_unknown_el1", "a0 f2 1c d5")
    func64(seg_start, seg_end, "_boot_check_panic", "49 00 c0 d2  09 21 a8 f2")
    func64(seg_start, seg_end, "_verify_pkcs1_sig", "68 0e 00 54  a1 12 40 f9")
    func64(seg_start, seg_end, "_parse_extensions", "e9 23 00 91  35 81 00 91")
    func64(seg_start, seg_end, "_read_ctrr_lock", "40 f2 3c d5")
    func64(seg_start, seg_end, "_reload_cache", "1f 87 08 d5")
    func64(seg_start, seg_end, "_parse_chain", "5a 3d 00 12  77 3d 00 12")
    func64(seg_start, seg_end, "_memset", "21 1c 40 92  e3 c3 00 b2")
    func64(seg_start, seg_end, "_memcpy", "63 80 00 91  63 e8 7b 92")
    func64(seg_start, seg_end, "_bzero", "63 e4 7a 92  42 00 00 8b")
    func64(seg_start, seg_end, "_panic", "e8 03 00 91  16 81 00 91")  # doubt


def accept_file(file_descriptor, file_name):
    file_descriptor.seek(0x0, idaapi.SEEK_END)
    file_size = file_descriptor.tell()

    file_descriptor.seek(0xc00)
    search = file_descriptor.read(0x17)

    # 64bit (A11 and later)
    if search[:17] == b"private_build...(":
        return {
            "format": "SEPROM (AArch64)",
            "processor": "arm",
            "file_name": file_name,
            "bits": 64,
            "base_addr": 0x240000000,
            "file_size": file_size
        }

    file_descriptor.seek(0x800)
    search = file_descriptor.read(0x10)

    # 32bit (A10X and prior)
    if search[:11] == b"AppleSEPROM":
        return {
            "format": "SEPROM (AArch32)",
            "processor": "arm",
            "file_name": file_name,
            "bits": 32,
            "base_addr": 0x10000000,
            "file_size": file_size
        }

    return IDA_REJECT_FILE


def load_file(file_descriptor, flags, format_name):
    print("[sephelper]: starting...")
    print(f"[sephelper]: {flags}, {format_name}")

    file_format = FORMATS[format_name]
    file_descriptor.seek(0x0, idaapi.SEEK_END)
    file_size = file_descriptor.tell()

    if file_format["bits"] == 32:
        print("[sephelper]: detected a 32bit SEPROM !")
        idaapi.set_processor_type("arm:armv7-m", idaapi.SETPROC_LOADER_NON_FATAL)
        idaapi.get_inf_structure().lflags |= idaapi.LFLG_PC_FLAT
    else:
        print("[sephelper]: detected a 64bit SEPROM !")
        idaapi.set_processor_type("arm", idaapi.SETPROC_LOADER_NON_FATAL)
        idaapi.get_inf_structure().lflags |= idaapi.LFLG_64BIT

    if (flags & idaapi.NEF_RELOAD) != 0:
        return 1

    segment = idaapi.segment_t()

    bitness = IDASegmentType.from_bits(file_format['bits'])

    segment.bitness = bitness.value
    segment.start_ea = 0x0
    segment.end_ea = file_size

    idaapi.add_segm_ex(segment, "SEPROM", "CODE", idaapi.ADDSEG_OR_DIE)

    file_descriptor.seek(0x0)

    file_descriptor.file2base(0x0, 0x0, file_size, False)

    print("[sephelper]: adding entry point...")

    idaapi.add_entry(0x0, 0x0, "_start", 1)

    idaapi.add_func(0)

    ea = file_format['base_addr']
    print("[sephelper]: base_addr = 0x%x" % ea)

    idaapi.rebase_program(ea, idc.MSF_NOFIX)

    print("[sephelper]: analyzing...")
    segment_end = idc.get_segm_attr(ea, idc.SEGATTR_END)

    for prologue in PROLOGUES[bitness]:
        while ea != idc.BADADDR:
            ea = idaapi.find_binary(ea, segment_end, prologue, 0x10, idaapi.SEARCH_DOWN)

            if ea != idc.BADADDR:
                ea = ea - 0x2

                if (ea % 0x4) == 0 and idaapi.get_full_flags(ea) < 0x200:
                    idaapi.add_func(ea)

                ea = ea + 0x4

    idc.plan_and_wait(file_format['base_addr'], segment_end)

    print('[sephelper]: finding some functions...')

    find_function(segment.start_ea, segment_end)

    print('[sephelper]: done !')

    return 1


# noinspection PyPep8Naming
def PLUGIN_ENTRY():
    class SEPROMLoaderPlugin(idaapi.plugin_t):
        flags = idaapi.PLUGIN_PROC | idaapi.PLUGIN_HIDE
        comment = "Apple SEPROM Loader"
        help = "Runs transparently"
        wanted_name = "ARM32/ARM64 SEPROM Loader"
        wanted_hotkey = str()
        hook = None

        def init(self):
            pass

        def run(self, arg):
            # TODO: Allow re-analysis of any given file
            pass

        def term(self):
            pass

    return SEPROMLoaderPlugin()
