# !/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
import os
import multiprocessing
import signal
import cStringIO

try:
    from capstone import Cs
    from capstone import CS_ARCH_X86
    from capstone import CS_MODE_32
    from capstone import CS_MODE_64
except ImportError:
    print "Warning: Capstone not found"


class Instruction:
    def __init__(self, offset, va, address, mnemonic, op_str, size, bytes, cache_only):
        self.offset = offset
        self.va = va
        self.address = address
        self.mnemonic = mnemonic
        self.op_str = op_str
        self.size = size
        self.bytes = bytes
        self.ifrom = list()  # VA of previous instructions
        self.ito = list()    # VA of next instructions
        self.to_succ = None
        self.to_other = None
        self.cache_only = cache_only 

    def add_ifrom(self, inst_offset):
        self.ifrom.append(inst_offset)

    def add_ito(self, inst_offset, from_pred=True):
        self.ito.append(inst_offset)

        if from_pred:
            if self.to_succ is None:
                self.to_succ = inst_offset
            else:
                print("Warning: Should only have one successor node.")
        else:
            if self.to_other is None:
                self.to_other = inst_offset
            else:
                print("Warning: Should only have one \"other\" node.")

    def __str__(self):
        ba = " ".join([hex(h)[2:].zfill(2) for h in self.bytes])

        prev = ["0x%08X" % x for x in self.ifrom]
        next = ["0x%08X" % x for x in self.ito]
        m = ""
        if self.mnemonic in ['ret', 'retf', 'jmp', 'jmpf']:
            m += "0x%08X:\t\t\t%-30s\t%-10s\t%-40s\t%-35s%-35s\n" % (
                self.va, ba, self.mnemonic, self.op_str, next, prev)
            m += "0x%08X ; --------------------------------------------------------------\n" % (self.va)
            m += "0x%08X " % (self.va)
        elif len(self.ifrom) >= 2:
            m += "0x%08X\n" % (self.va)
            m += "0x%08X  loc_%08X:\n" % (self.va, self.va)
            m += "0x%08X:\t\t\t%-30s\t%-10s\t%-40s\t%-35s%-35s" % (
                self.va, ba, self.mnemonic, self.op_str, next, prev)
        else:
            m += "0x%08X:\t\t\t%-30s\t%-10s\t%-40s\t%-35s%-35s" % (
                self.va, ba, self.mnemonic, self.op_str, next, prev)
        return m


class GenericDisassembler:
    def __init__(self, arch, mode):
        self.arch = arch
        self.mode = mode
        self.capstone = Cs(self.arch, self.mode)

        self.prologues = {
            # Triple backslash (\\\) are needed to escape bytes in the compiled regex
            CS_MODE_32: [
                "\\\x55\\\x89\\\xE5",  # push ebp & mov ebp, esp
                "\\\x55\\\x8B\\\xEC",  # push ebp & mov ebp, esp
                "\\\x55\\\x8b\\\x6c\\\x24",  # push ebp & mov ebp, [esp+?]
            ],
            CS_MODE_64: [
                "\\\x55\\\x48\\\x89\\\xE5",  # push rbp & mov rbp, rsp
            ]
        }[mode]

        self.conditional_jmp_mnemonics = {'jz', 'je', 'jcxz', 'jecxz', 'jrcxz', 'jnz', 'jp', 'jpe', 'jnp', 'ja', 'jae', 'jb', 'jbe', 'jg', 'jge', 'jl', 'jle', 'js', 'jns', 'jo', 'jno', 'jecxz', 'loop', 'loopne', 'loope', 'jne'}
        self.x86_32_registers = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp'}
        self.max_instruction_size = 16

    def linear_sweep_cache(self, data, offset, insts, bin_instance, verbose=False):
        curr_offset = offset
        try:
            inst_va = self.get_va_from_offset(bin_instance, curr_offset)
            instructions = self.capstone.disasm_lite(data[offset:], inst_va)

            curr_offset = offset
            for (address, size, mnemonic, op_str) in instructions:
                inst = Instruction(
                    offset=curr_offset,
                    va=inst_va,
                    address=address,
                    mnemonic=mnemonic,
                    op_str=op_str,
                    size=size,
                    bytes=data[curr_offset:curr_offset+size],
                    cache_only=True,
                )

                insts[curr_offset] = inst
                curr_offset += size
                inst_va += size
        except Exception, e:
            print "WARNING:", repr(e)
        return insts

    def _dis(self, data, offset, insts, bin_instance, iat_api=dict(), verbose=False, ifrom=None, from_pred=True):
        '''
            <insts> is a dict like {'offset': <Instruction>}
        '''

        args_queue = []
        args_queue.append((offset, ifrom, from_pred))

        while args_queue != []:
            offset, ifrom, from_pred = args_queue.pop(0)

            if offset is None:
                continue

            inst = None
            if offset in insts:
                inst = insts[offset]
                if inst.cache_only:
                    inst.cache_only = False
                else:
                    if ifrom:
                        inst.add_ifrom(ifrom.offset)
                        insts[ifrom.offset].add_ito(inst.offset, from_pred)
                    continue

            if inst is None:
                try:
                    inst_va = self.get_va_from_offset(bin_instance, offset)
                    (address, size, mnemonic, op_str) = self.capstone.disasm_lite(data[offset:offset+self.max_instruction_size], inst_va, count=1).next()

                    inst = Instruction(
                        offset=offset,
                        va=inst_va,
                        address=address,
                        mnemonic=mnemonic,
                        op_str=op_str,
                        size=size,
                        bytes=data[offset:offset+size],
                        cache_only=False,
                    )
                    insts[inst.offset] = inst

                except Exception, e:
                    if verbose:
                        print "WARNING:", repr(e)
                    continue

            if ifrom:
                insts[inst.offset].add_ifrom(ifrom.offset)
                insts[ifrom.offset].add_ito(inst.offset, from_pred)

            # No child
            if inst.mnemonic in ['ret', 'retf']:
                pass

            # 1 remote child
            elif inst.mnemonic in ['jmp', 'jmpf']:
                if "word ptr [0x" in inst.op_str:
                    iat_va = int(inst.op_str.split('[')[1].split(']')[0], 16)

                    if iat_va in iat_api:
                        inst.op_str = iat_api[iat_va]
                else:
                    try:
                        remote_offset = self.get_offset_from_va(bin_instance, int(inst.op_str, 16))
                        if remote_offset is not None:
                            args_queue.insert(0, (remote_offset, insts[inst.offset], False))
                    except Exception, e:
                        if verbose:
                            print "WARNING:", repr(e)
                        pass

            # 2 children (next, then remote) - except call
            elif inst.mnemonic in self.conditional_jmp_mnemonics:
                next_offset = inst.offset + inst.size

                args_queue.insert(0, (next_offset, insts[inst.offset], True))

                # Call to Imported API (in IAT)
                # dword ptr [0x........] or qword ptr [0x........]
                if "word ptr [0x" in inst.op_str:
                    iat_va = int(inst.op_str.split('[')[1].split(']')[0], 16)

                    if iat_va in iat_api:
                        inst.op_str = iat_api[iat_va]
                elif inst.op_str in ['eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'esp', 'ebp']:
                    pass
                else:
                    try:
                        remote_offset = self.get_offset_from_va(bin_instance, int(inst.op_str, 16))
                    except Exception, e:
                        if verbose:
                            print "WARNING:", repr(e)
                        continue

                args_queue.insert(1, (remote_offset, insts[inst.offset], False))

            # 2 children (next, then remote) - call
            elif inst.mnemonic in ['call']:

                next_offset = inst.offset + inst.size
                remote_offset = None

                args_queue.insert(0, (next_offset, insts[inst.offset], True))

                # Call to Imported API (in IAT)
                # dword ptr [0x........] or qword ptr [0x........]
                if "word ptr [0x" in inst.op_str:
                    iat_va = int(inst.op_str.split('[')[1].split(']')[0], 16)

                    if iat_va in iat_api:
                        inst.op_str = iat_api[iat_va]
                elif inst.op_str in self.x86_32_registers:
                    pass
                else:
                    try:
                        remote_offset = self.get_offset_from_va(bin_instance, int(inst.op_str, 16))
                    except Exception as e:
                        if verbose:
                            print "WARNING:", repr(e)
                        pass

                if remote_offset:
                    args_queue.insert(1, (remote_offset, insts[inst.offset], False))

            # 1 child (next) - basic instruction
            else:
                next_offset = inst.offset + inst.size
                args_queue.insert(0, (next_offset, insts[inst.offset], True))

        return insts

    def dis_prologues(self, data, bin_instance, iat_api, insts, verbose):
        prologues_re = "|".join(self.prologues)
        compiled_re = re.compile(prologues_re)
        for m in compiled_re.finditer(data):
            function_offset = m.start()

            inst = insts.get(function_offset, None)
            if inst is None or inst.cache_only:
                insts = self._dis(data=data, offset=function_offset, iat_api=iat_api, bin_instance=bin_instance, insts=insts, verbose=verbose)
        return insts

    def dis(self, data, offset, iat_api, bin_instance, verbose=False):
        '''
            data: raw binary of full PE
            va: va of the instruction located at <data[index]>
            iat_api: dict of imported API like {VA_IN_IAT: API_NAME}
        '''

        insts = dict()
        insts = self.linear_sweep_cache(data=data, offset=offset, insts=insts, bin_instance=bin_instance, verbose=verbose)
        insts = self._dis(data=data, offset=offset, iat_api=iat_api, bin_instance=bin_instance, insts=insts, verbose=verbose)

        # Exploration of the exported functions
        self._dis_exported_funcs(bin_instance=bin_instance, insts=insts, data=data, verbose=verbose, iat_api=iat_api)

        # Search for unrecognized functions from their prolog function
        insts = self.dis_prologues(data=data, bin_instance=bin_instance, iat_api=iat_api, insts=insts, verbose=verbose)

        return insts

    def display(self, insts, offset_from=0):
        for offset, inst in sorted(insts.iteritems()):
            if offset >= offset_from:
                print inst

    def export_to_dot(self, insts, oep_offset, displayable=True):
        '''
            Export the intruction graph to DOT format
        '''
        nodes = cStringIO.StringIO()
        edges = cStringIO.StringIO()
        dot = cStringIO.StringIO()

        header = "digraph G {\n"
        footer = "}"

        if displayable:

            for offset, inst in sorted(insts.iteritems()):
                if not inst.cache_only:
                    if inst.op_str == "":
                        inst_str = "%s" % inst.mnemonic
                    else:
                        inst_str = "%s %s" % (inst.mnemonic, inst.op_str)

                    if offset != oep_offset:
                        nodes.write(('"%X" [label="%s", address="0x%X", inst="%s", '
                                     'style="", shape=box, fillcolor="white"]\n') % (
                            inst.va,
                            "%016X: %s %s" % (inst.va, inst.mnemonic, inst.op_str),
                            inst.va,
                            inst_str
                        ))
                    else:
                        nodes.write(('"%X" [label="%s", address="0x%X", inst="%s", '
                                     'style="", shape=box, fillcolor="white", root=true]\n') % (
                            inst.va,
                            "%016X: %s %s" % (inst.va, inst.mnemonic, inst.op_str),
                            inst.va,
                            inst_str
                        ))

                    if inst.to_succ is not None:
                        edges.write(('"%X" -> "%X" [label=0, color=%s, child_number=1]\n') % (
                            inst.va,
                            insts[inst.to_succ].va,
                            "black"
                        ))

                    if inst.to_other is not None:
                        edges.write(('"%X" -> "%X" [label=1, color=%s, child_number=2]\n') % (
                            inst.va,
                            insts[inst.to_other].va,
                            "red"
                        ))
        else:

            for offset, inst in sorted(insts.iteritems()):
                if not inst.cache_only:
                    if inst.op_str == "":
                        inst_str = "%s" % inst.mnemonic
                    else:
                        inst_str = "%s %s" % (inst.mnemonic, inst.op_str)

                    if offset != oep_offset:
                        nodes.write(('"%X" [inst="%s", address="0x%X"]\n') % (
                            inst.va,
                            inst_str,
                            inst.va
                        ))
                    else:
                        nodes.write(('"%X" [inst="%s", address="0x%X", root=true]\n') % (
                            inst.va,
                            inst_str,
                            inst.va
                        ))

                    if inst.to_succ is not None:
                        edges.write(('"%X" -> "%X" [child_number=1]\n') % (inst.va, insts[inst.to_succ].va))

                    if inst.to_other is not None:
                        edges.write(('"%X" -> "%X" [child_number=2]\n') % (inst.va, insts[inst.to_other].va))

        dot.write(header)
        dot.write(nodes.getvalue())
        dot.write(edges.getvalue())
        dot.write(footer)

        return dot.getvalue()


class PEDisassembler(GenericDisassembler):
    def get_offset_from_rva(self, pe, rva):
        remote_offset = pe.get_offset_from_rva(rva)
        return remote_offset

    def get_offset_from_va(self, pe, rva):
        return self.get_offset_from_rva(pe, rva - self.get_image_base_rva(pe))

    def get_rva_from_offset(self, pe, offset):
        return pe.get_rva_from_offset(offset)

    def get_va_from_offset(self, pe, offset):
        return self.get_rva_from_offset(pe, offset) + self.get_image_base_rva(pe)

    def get_image_base_rva(self, pe):
        return pe.OPTIONAL_HEADER.ImageBase

    def _dis_exported_funcs(self, bin_instance, insts, data, verbose, iat_api=dict()):
        """
        Disassemble all the exported functions.

        Args:
            pe (PE) : PE Object
            insts (Dict)  : Dictionary of instructions
        """

        # Export table
        try:
            export_table = bin_instance.DIRECTORY_ENTRY_EXPORT.symbols
        except Exception, e:
            if verbose:
                print "WARNING:", repr(e)
            export_table = None

        if export_table is not None:
            for exp in export_table:
                inst = insts.get(exp, None)
                if inst is None or inst.cache_only:
                    insts = self._dis(data=data,
                                 offset=exp.address,
                                 iat_api=iat_api,
                                 bin_instance=bin_instance,
                                 insts=insts,
                                 verbose=verbose)


class ELFDisassembler(GenericDisassembler):
    def __init__(self, arch, mode, elf):
        GenericDisassembler.__init__(self, arch, mode)

        # We cache ELF properties for faster access
        self.image_base_rva = None
        for section in elf.iter_sections():
            self.image_base_rva =  section['sh_addr'] - section['sh_offset']
            break

        self.n_segments = 0
        self.seg_offset_low = []
        self.seg_offset_high = []
        self.seg_rva_low = []
        self.seg_rva_high = []
        self.seg_pvaddr = []
        self.seg_poffset = []
        self.seg_pvaddr_minus_poffset = []
        for segment in elf.iter_segments():
            self.n_segments += 1
            self.seg_offset_low.append(segment['p_offset'])
            self.seg_offset_high.append(segment['p_offset'] + segment['p_filesz'])
            self.seg_rva_low.append(segment['p_vaddr'])
            self.seg_rva_high.append(segment['p_vaddr'] + segment['p_memsz'])
            self.seg_pvaddr_minus_poffset.append(segment['p_vaddr'] - segment['p_offset'])

    def get_offset_from_rva(self, elf, rva):
        for s in xrange(self.n_segments):
            if self.seg_rva_low[s] <= rva < self.seg_rva_high[s]:
                return rva - self.seg_pvaddr_minus_poffset[s]
        return None

    def get_offset_from_va(self, elf, va):
        return self.get_offset_from_rva(elf, va - self.get_image_base_rva(elf))

    def get_rva_from_offset(self, elf, offset):
        for s in xrange(self.n_segments):
            if self.seg_offset_low[s] <= offset < self.seg_offset_high[s]:
                return self.seg_pvaddr_minus_poffset[s] + offset
        return None

    def get_va_from_offset(self, elf, offset):
        return self.get_rva_from_offset(elf, offset) + self.image_base_rva

    def get_image_base_rva(self, elf):
        return self.image_base_rva

    def _dis_exported_funcs(self, data, bin_instance, insts, verbose):
        """
        Disassemble all the exported functions.

        Args:
            elf (ELFFile) : ELF Object
            insts (Dict)  : Dictionary of instructions
        """
        image_base = self.get_image_base_rva(bin_instance)

        if bin_instance.get_section_by_name('.dynsym') is not None:
            # Dynsym
            for sym in bin_instance.get_section_by_name('.dynsym').iter_symbols():

                info = sym.entry

                # If the symbol is an exported function
                if info.st_info['type'] == 'STT_FUNC' and \
                   info.st_info['bind'] == 'STB_GLOBAL':

                    # If this is a new non-empty function

                    inst = insts.get(info.st_value, None)
                    if info.st_value != 0 and (inst is None or inst.cache_only):

                        offset = self.get_offset_from_rva(
                            bin_instance,
                            (info.st_value - image_base)
                        )

                        if verbose:
                            print 'Func %s found at offset 0x%08X, RVA: 0x%08X' % (
                                sym.name,
                                offset,
                                info.st_value
                            )

                        insts = self._dis(data=data,
                                     offset=offset,
                                     bin_instance=bin_instance,
                                     insts=insts,
                                     verbose=verbose)

    def dis(self, data, offset, iat_api, bin_instance, verbose=False):
        '''
            data: raw binary of full elf
            va: va of the instruction located at <data[index]>
            iat_api: dict of imported API like {VA_IN_IAT: API_NAME}

        '''
        insts = dict()

        insts = self.linear_sweep_cache(data=data, offset=offset, insts=insts, bin_instance=bin_instance, verbose=verbose)
        insts = self._dis(data=data, offset=offset, bin_instance=bin_instance, insts=insts, verbose=verbose)

        # Function 'start' jumps on function 'main' with a dynamic jump. 'main' address is given in argument
        # so we get that argument and we continue to disassemble
        '''
        .text:0000000000XXX89F                 mov     r8, offset fini ; fini
        .text:0000000000XXX8A6                 mov     rcx, offset init ; init
        .text:0000000000XXX8AD                 mov     rdi, offset main ; main
        .text:0000000000XXX8B4                 call    ___libc_start_main

        Note that the 'mov' can also be 'lea':
            lea rdi, [rip + 0x3baa]
            lea rdi, [rip + 0x3b33]
            lea rdi, [rip - 0x1106]
            call    cs:__libc_start_main_ptr
        '''
        
        for offset, inst in sorted(insts.iteritems()):
            # mov     r8, offset fini ; fini
            i1 = inst

            # mov     rcx, offset init ; init
            if len(i1.ito) != 1:
                continue
            i2 = insts[i1.ito[0]]

            # mov     rdi, offset main ; main
            # mov     rcx, offset init ; init
            if len(i2.ito) != 1:
                continue
            i3 = insts[i2.ito[0]]

            # call    ___libc_start_main
            # mov     rcx, offset init ; init
            if len(i3.ito) != 1:
                continue
            i4 = insts[i3.ito[0]]
        

            all_mov = i1.mnemonic == "mov" and i2.mnemonic == "mov" and i3.mnemonic == "mov"
            all_lea = i1.mnemonic == "lea" and i2.mnemonic == "lea" and i3.mnemonic == "lea"
            if (all_mov or all_lea) and i4.mnemonic == "call":
                pass
            else:
                continue

            try:
                if all_mov:
                    rva_fini = int(i1.op_str.split(", 0x")[1], 16)
                    rva_init = int(i2.op_str.split(", 0x")[1], 16)
                    rva_main = int(i3.op_str.split(", 0x")[1], 16)
                else:
                    # Then all_lea
                    if "+" in i1.op_str:
                        rva_fini = i2.address + int(i1.op_str.split("+ 0x")[1][:-1], 16)
                    else:
                        # "-" in i1.op_str:
                        rva_fini = i2.address - int(i1.op_str.split("- 0x")[1][:-1], 16)

                    if "+" in i2.op_str:
                        rva_init = i3.address + int(i2.op_str.split("+ 0x")[1][:-1], 16)
                    else:
                        # "-" in i2.op_str:
                        rva_init = i3.address - int(i2.op_str.split("- 0x")[1][:-1], 16)

                    if "+" in i3.op_str:
                        rva_main = i4.address + int(i3.op_str.split("+ 0x")[1][:-1], 16)
                    else:
                        # "-" in i3.op_str:
                        rva_main = i4.address - int(i3.op_str.split("- 0x")[1][:-1], 16)

                insts = self._dis(data=data, offset=self.get_offset_from_rva(bin_instance, rva_fini), bin_instance=bin_instance, insts=insts, verbose=verbose)
                insts = self._dis(data=data, offset=self.get_offset_from_rva(bin_instance, rva_init), bin_instance=bin_instance, insts=insts, verbose=verbose)
                insts = self._dis(data=data, offset=self.get_offset_from_rva(bin_instance, rva_main), bin_instance=bin_instance, insts=insts, verbose=verbose)

                break
            except Exception, e:
                if verbose:
                    print "WARNING:", repr(e)
                continue

        # Exploration of the exported functions
        self._dis_exported_funcs(data=data, bin_instance=bin_instance, insts=insts, verbose=verbose)

        # Search for unrecognized functions from their prolog function
        insts = self.dis_prologues(data=data, bin_instance=bin_instance, iat_api=iat_api, insts=insts, verbose=verbose)

        return insts


class RawDisassembler(GenericDisassembler):
    def get_offset_from_rva(self, raw, rva):
        return rva

    def get_offset_from_va(self, raw, rva):
        return rva - self.get_image_base_rva(raw)

    def get_rva_from_offset(self, raw, offset):
        return offset

    def get_va_from_offset(self, raw, offset):
        return self.get_rva_from_offset(raw, offset) + self.get_image_base_rva(raw)

    def get_image_base_rva(self, raw):
        return 0

    def _dis_exported_funcs(self, bin_instance, insts, data, verbose, iat_api=dict()):
        return


def write_to_file(path, data):
    try:
        f = open(path, "wb")
        f.write(data)
        f.close()
    except:
        print "WARNING: Could not write data to", path


def disassemble_pe(pe_data = None, pe_path = None, dot_path = None, print_listing=False, readable=False, verbose=False):
    if pe_data is None and pe_path is None:
        print "ERROR: Missing PE path or data."
        return None

    if pe_data is None:
        pe_data = open(pe_path, "rb").read()

    try:
        import pefile
        pe = pefile.PE(data=pe_data)
    except Exception, e:
        if verbose:
            print "WARNING:", repr(e)
        print "ERROR: pefile could not parse PE."
        return None

    arch = CS_ARCH_X86
    is_32 = pe.FILE_HEADER.Characteristics & 0x0100
    mode = CS_MODE_32 if is_32 else CS_MODE_64

    oep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(oep_rva)
    if code_section is None:
        print "ERROR: pefile could not find code section."
        return None

    oep_offset = oep_rva - code_section.VirtualAddress + code_section.PointerToRawData

    iat_dict = dict()

    try:
        import_table = pe.DIRECTORY_ENTRY_IMPORT.symbols
    except Exception, e:
        if verbose:
            print "WARNING:", repr(e)
        import_table = None

    if import_table is not None:
        for entry in import_table:
            for imp in entry.imports:
                if entry.dll is None:
                    entry_str = ""
                else:
                    entry_str = entry.dll

                if imp.name is None:
                    imp_str = ""
                else:
                    imp_str = imp.name

                iat_dict[imp.address] = entry_str + "." + imp_str

    disass = PEDisassembler(arch=arch, mode=mode)
    insts = disass.dis(data=pe_data, offset=oep_offset, iat_api=iat_dict, bin_instance=pe, verbose=verbose)

    if dot_path is not None:
        dot = disass.export_to_dot(insts=insts, oep_offset=oep_offset, displayable=readable)
        write_to_file(dot_path, dot)

    if print_listing:
        disass.display(insts, offset_from=0)

    return True


def disassemble_elf(elf_data = None, elf_path = None, dot_path = None, print_listing=False, readable=False, verbose=False):
    if elf_path is None:
        print "ERROR: Missing ELF path."
        return None

    from elftools.elf.elffile import ELFFile
    if elf_data is None:
        elf_data = open(elf_path, "rb").read()

    elf = ELFFile(cStringIO.StringIO(elf_data))

    arch = CS_ARCH_X86
    mode = CS_MODE_64 if elf.elfclass == 64 else CS_MODE_32

    oep_rva = elf.header.e_entry

    def get_offset_from_rva(elf, offset):
        for section in elf.iter_sections():
            try:
                if section['sh_addr'] <= oep_rva < section['sh_addr'] + section['sh_size']:
                    return section['sh_offset'] + (oep_rva - section['sh_addr'])
            except Exception, e:
                if verbose:
                    print "WARNING:", repr(e)
                continue
        return None

    oep_offset = get_offset_from_rva(elf, oep_rva)

    if oep_offset is None:
        print "ERROR: Cannot retrieve entry point offset from RVA (0x%08X)." % (elf.header.e_entry)
        return None

    disass = ELFDisassembler(arch=arch, mode=mode, elf=elf)
    insts = disass.dis(data=elf_data, offset=oep_offset, iat_api={}, bin_instance=elf, verbose=verbose)

    if dot_path is not None:
        dot = disass.export_to_dot(insts=insts, oep_offset=oep_offset, displayable=readable)
        write_to_file(dot_path, dot)

    if print_listing:
        disass.display(insts, offset_from=0)

    return True


def disassemble_raw(raw_data = None, raw_path = None, dot_path = None, print_listing=False, readable=False,
                    raw_64=False, entrypoint=None, verbose=False):
    if raw_data is None and raw_path is None:
        print "ERROR: Missing PE path or data."
        return None

    if raw_data is None:
        raw_data = open(raw_path, "rb").read()

    arch = CS_ARCH_X86
    mode = CS_MODE_64 if raw_64 else CS_MODE_32

    if entrypoint is not None:
        oep_offset = entrypoint
    else:
        oep_offset = 0

    iat_dict = dict()

    disass = RawDisassembler(arch=arch, mode=mode)
    insts = disass.dis(data=raw_data, offset=oep_offset, iat_api=iat_dict, bin_instance=None, verbose=verbose)

    if dot_path is not None:
        dot = disass.export_to_dot(insts=insts, oep_offset=oep_offset, displayable=readable)
        write_to_file(dot_path, dot)

    if print_listing:
        disass.display(insts, offset_from=0)

    return True


def disassemble_file(bin_data = None, dir_path=None, bin_path=None, dot_path=None, print_listing=False, readable=False, raw=False, raw_64=False, entrypoint=None, verbose=False, use_existing=False, skip_disassembly=False):
    return_path = dot_path
    if dir_path is not None:
        # Binary file comes from directly being recursively traversed, return dir path
        return_path = dir_path

    if skip_disassembly or (use_existing and os.path.exists(dot_path)):
        return return_path

    if verbose:
        print "Disassembling", bin_path

    if bin_data is None:
        if bin_path is None:
            return None
        bin_data = open(bin_path, "rb").read()

    if raw:
        if disassemble_raw(raw_data=bin_data, raw_path=bin_path, dot_path=dot_path, print_listing=print_listing,
                           readable=readable, raw_64=raw_64, entrypoint=entrypoint, verbose=verbose):
            return return_path
    elif bin_data[0:2] == "MZ":
        if disassemble_pe(pe_data=bin_data, pe_path=bin_path, dot_path=dot_path, print_listing=print_listing,
                          readable=readable, verbose=verbose):
            return return_path
    elif bin_data[0:4] == "\x7fELF":
        if disassemble_elf(elf_data=bin_data, elf_path=bin_path, dot_path=dot_path, print_listing=print_listing,
                           readable=readable, verbose=verbose):
            return return_path
    else:
        if verbose:
            print("WARNING: Test file " + bin_path + " does not seem to be a PE/ELF or dot file. Use raw option if raw file.")
    return None


def disas_worker(arg):
    return disassemble_file(bin_path=arg[0], dir_path=arg[1], dot_path=arg[2], print_listing=arg[3], readable=arg[4], verbose=arg[5], raw=arg[6], raw_64=arg[7], use_existing=arg[8], skip_disassembly=arg[9])


def timeout_worker(*arg):
    # One thread to process this file, with a timeout
    p = multiprocessing.dummy.Pool(1)
    res = p.apply_async(disas_worker, arg)
    try:
        out = res.get(timeout=arg[0][-1])
        p.close()
    except multiprocessing.TimeoutError:
        print "WARNING: Disassembly timeout for", arg[0][0]
        p.terminate()
        p.close()
        out = None

    return out


def disassemble_files(path_dir_list, dot_path_suffix, dot_dir=None, multiprocess=True, n_processes=4, print_listing=False, readable=False, raw=False, raw_64=False, verbose=False, use_existing=False, timeout=0, skip_disassembly=False):
    dot_path_list = []
    arg_list = []

    if path_dir_list is not None and path_dir_list != []:
        if multiprocess:
            if isinstance(timeout, int) or (isinstance(timeout, str) and timeout.isdigit()):
                i = int(timeout)
                if i == 0:
                    timeout_sec = 31536000
                else:
                    timeout_sec = i
            else:
                timeout_sec = 31536000

            for path, dir_arg_path in path_dir_list:
                if dot_dir is None:
                    dot_path = path + dot_path_suffix
                else:
                    dot_path = os.path.join(dot_dir, os.path.basename(path) + dot_path_suffix)
                arg_list.append((path, dir_arg_path, dot_path, print_listing, readable, verbose, raw, raw_64, use_existing, skip_disassembly, timeout_sec))

            original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)

            # 8 tasks per child max: regenerate workers to free "lost" memory
            # TODO: make sure memory is freed when timeout is reached
            pool = multiprocessing.Pool(processes=min(n_processes, len(arg_list)), maxtasksperchild=8)
            signal.signal(signal.SIGINT, original_sigint_handler)
            ret = None

            try:
                res = pool.map_async(timeout_worker, arg_list, chunksize=1)

                # Need timeout (one year) so SIGINT is not ignored
                ret = res.get(timeout=31536000)
            except KeyboardInterrupt:
                pool.terminate()
            else:
                pool.close()

            if ret is not None:
                dot_path_list = [p for p in ret if p is not None]
        else:
            for path, dir_path in path_dir_list:
                r = disassemble_file(bin_path=path, dir_path=dir_path, dot_path=path+dot_path_suffix,
                                     print_listing=print_listing, readable=readable, raw=raw, raw_64=raw_64,
                                     verbose=verbose, use_existing=use_existing, skip_disassembly=skip_disassembly)
                if r is not None:
                    dot_path_list.append(r)
    return dot_path_list


if __name__ == "__main__":
    if len(sys.argv) == 2:
        sys.setrecursionlimit(1000000)
        bin_path = sys.argv[1]
        dot_path = bin_path + ".grapcfg"
        disassemble_file(bin_path=bin_path, dot_path=dot_path, verbose=False)
