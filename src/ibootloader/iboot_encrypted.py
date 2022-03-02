#
#  iBootLoader | ibootloader
#  iboot_encrypted.py
#
#  Loader for encrypted im4ps
#
#  This file is part of iBootLoader. iBootLoader is free software that
#  is made available under the MIT license. Consult the
#  file "LICENSE" that is distributed together with this file
#  for the exact licensing terms.
#
#  Copyright (c) kat 2021.
#

import random, string, os

from disassembler_api.api import API, DisassemblerFile, Segment, Bitness, ProcessorType, SegmentType, SearchDirection
from kimg4.img4 import get_keybags, aes_decrypt

from .cache import Cache


class IBootEncryptedLoader:
    def __init__(self, api: API, fd, bitness, version_string):
        self.name = "iBoot Encrypted Loader"
        self.api: API = api
        self.file: DisassemblerFile = self.api.get_disasm_file(fd)
        self.cache = Cache()

        self.deleteme = []

        self.bitness = bitness
        self.version_string = version_string

        self.segments = []
        self.code_segment: Segment = None
        self.ram_segment: Segment = None
        self.string_start = 0

    def decrypt(self):
        # jesus christ, ok
        temp_filename = '.temp_' + ''.join(random.choice(string.ascii_lowercase) for i in range(10))
        temp_filename_dec = '.temp_' + ''.join(random.choice(string.ascii_lowercase) for i in range(10))

        # grab the ida file pointer
        idafd = self.file.fd
        # make sure we're at 0
        idafd.seek(0)

        idafd_size = idafd.size()
        # load the entirety of file contents into a variable
        im4p_bytes = idafd.read(idafd_size)

        # write the bytes to a file so the img4 code can load it
        with open(temp_filename, 'wb') as temp_undec:
            temp_undec.write(im4p_bytes)
        bags = None
        # now send the file pointer for that to the img4 code; get our keybags
        with open(temp_filename, 'rb') as fp:
            bags = get_keybags(fp)
            print('keybags:')
            for bag in bags:
                print('  ' + bag)

        keybag = bags[0]

        iv = ''
        key = ''

        if self.cache.is_keybag_in_cache(keybag):
            print('[+] Found keybag in cache')
            keybag_dict = self.cache.keybag_from_cache(keybag)
            iv = keybag_dict['iv']
            key = keybag_dict['key']
        else:
            print('[*] Keybag not yet in cache, enter IV/Key')
            iv = self.api.ask_str('AES IV')
            key = self.api.ask_str('AES KEY')
            print('[*] Saving keybag to cache')
            self.cache.cache_keybag(keybag, iv, key)

        # load in the im4p dumped from ida we wrote earlier
        with open(temp_filename, 'rb') as fp:
            with open(temp_filename_dec, 'wb') as out_fp:
                # invoke the aes code and decrypt the dumped fp, then save that to the next file
                aes_decrypt(fp, key, iv, out_fp)

        # read some basic values from the saved, decrypted fp
        with open(temp_filename_dec, 'rb') as in_fp:
            in_fp.seek(0x0)
            bn = in_fp.read(0x4)
            in_fp.seek(0x200)
            ver_bin = in_fp.read(0x30)
            ver_str = ver_bin.decode()
            version_string = "%s" % (ver_str)
            bitness = Bitness.Bitness32 if b'\xea' in bn else Bitness.Bitness64

            self.bitness = bitness
            self.version_string = version_string

        # we can just overwrite the file pointer with our own
        # ida bitches about this but it works
        idafd.close()
        idafd.open(temp_filename_dec)

        # add the temp files to the deletion queue
        # we cant delete these just yet, IDA needs to read the mem to load it into the program
        self.deleteme.append(temp_filename)
        self.deleteme.append(temp_filename_dec)

    def load(self):
        self.decrypt()

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

        sram_start_ptr = 0x300 + (7*ptr_size)

        self.code_segment = Segment("iBoot", base_addr, self.file.size, SegmentType.CODE, self.bitness)
        self.api.create_segment(self.code_segment)

        self.segments.append(self.code_segment)

        self.api.copy_da_file_to_segment(self.file, self.code_segment, 0)

        idafd = self.file.fd
        idafd.close()
        for filename in self.deleteme:
            os.remove(filename)

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

        #print([i for i in self.api.xrefs_to(pk_ea)])

        for xref in self.api.xrefs_to(pk_ea):
            func = self.api.get_function(xref.frm)
            if not func:
                #print(f'Bad Function {hex(xref.frm)}')
                continue
            function_address = func.start_ea
            if function_address == self.api.bad_address():
                print(f'  [-] {hex(xref)} func not found')
            break

        return function_address

