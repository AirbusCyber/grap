# !/usr/bin/env python
# -*- coding: utf-8 -*-

import re
import sys
import pefile
import os
import multiprocessing
import signal
from capstone import Cs
from capstone import CS_ARCH_X86
from capstone import CS_MODE_32
from capstone import CS_MODE_64
from cStringIO import StringIO


class Instruction:

    def __init__(self, id, offset, va, address, mnemonic, op_str, size, bytes):
        self.id = id
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


class PEDisassembler:
    def __init__(self, arch, mode):
        self.arch = arch
        self.mode = mode
        self.capstone = Cs(self.arch, self.mode)

        self.prologues = {
            CS_MODE_32: [
                "\x55\x89\xE5",  # push ebp & mov ebp, esp
                "\x55\x8B\xEC",  # push ebp & mov ebp, esp
            ],
            CS_MODE_64: [
                "\x55\x48\x89\xE5",  # push rbp & mov rbp, rsp
            ]
        }[mode]

    def dis(self, data, offset, iat_api, pe, verbose=False):
        '''
            data: raw binary of full PE
            va: va of the instruction located at <data[index]>
            iat_api: dict of imported API like {VA_IN_IAT: API_NAME}
        '''

        insts = dict()

        def _dis_exported_funcs(pe, insts, data, verbose):
            """
            Disassemble all the exported functions.

            Args:
                pe (PE) : PE Object
                insts (Dict)  : Dictionary of instructions
            """

            # Export table
            try:
                export_table = pe.DIRECTORY_ENTRY_EXPORT.symbols
            except:
                export_table = None

            if export_table is not None:
                for exp in export_table:
                    if exp not in insts:
                        insts = _dis(data=data,
                                     offset=exp.address,
                                     pe=pe,
                                     insts=insts,
                                     verbose=verbose)

        def _dis(data, offset, insts, pe, verbose=False, ifrom=None, from_pred=True):
            '''
                <insts> is a dict like {'offset': <Instruction>}
            '''

            if offset in insts:
                if ifrom:
                    insts[offset].add_ifrom(ifrom.offset)
                    insts[ifrom.offset].add_ito(insts[offset].offset, from_pred)

                return insts

            try:
                inst_va = pe.get_rva_from_offset(offset) + pe.OPTIONAL_HEADER.ImageBase
            except:
                if verbose:
                    print 'WARNING: RVA not found from offset', hex(offset)
                return insts

            try:
                i = self.capstone.disasm(data[offset:], inst_va, count=1).next()
            except:
                return insts

            inst = Instruction(
                id=i.id,
                offset=offset,
                va=inst_va,
                address=i.address,
                mnemonic=i.mnemonic,
                op_str=i.op_str,
                size=i.size,
                bytes=i.bytes,
            )
            insts[inst.offset] = inst

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
                        remote_offset = pe.get_offset_from_rva(int(inst.op_str, 16) - pe.OPTIONAL_HEADER.ImageBase)
                        insts = _dis(
                            data=data,
                            offset=remote_offset,
                            pe=pe,
                            insts=insts,
                            ifrom=insts[inst.offset],
                            from_pred=False,
                            verbose=verbose
                        )
                    except:
                        pass

            # 2 children (next, then remote) - except call
            elif inst.mnemonic in [
                    'jz', 'je', 'jcxz', 'jecxz', 'jrcxz', 'jnz', 'jp', 'jpe', 'jnp', 'ja', 'jae', 'jb', 'jbe',
                    'jg', 'jge', 'jl', 'jle', 'js', 'jns', 'jo', 'jno', 'jecxz', 'loop', 'loopne', 'loope',
                    'jne']:
                next_offset = inst.offset + inst.size

                try:
                    remote_offset = pe.get_offset_from_rva(int(inst.op_str, 16) - pe.OPTIONAL_HEADER.ImageBase)
                except:
                    if verbose:
                        print 'WARNING: RVA not found from offset', hex(int(inst.op_str, 16) - pe.OPTIONAL_HEADER.ImageBase)
                    return insts

                insts = _dis(
                    data=data,
                    offset=next_offset,
                    pe=pe,
                    insts=insts,
                    ifrom=insts[inst.offset],
                    from_pred=True,
                    verbose=verbose
                )

                insts = _dis(
                    data=data,
                    offset=remote_offset,
                    pe=pe,
                    insts=insts,
                    ifrom=insts[inst.offset],
                    from_pred=False,
                    verbose=verbose
                )

            # 2 children (next, then remote) - call
            elif inst.mnemonic in ['call']:

                next_offset = inst.offset + inst.size
                remote_offset = None

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
                        remote_offset = pe.get_offset_from_rva(int(inst.op_str, 16) - pe.OPTIONAL_HEADER.ImageBase)

                    except Exception as e:
                        # print "ERROR CALL: %s\n%s\n" % (e, inst)
                        pass

                insts = _dis(
                    data=data,
                    offset=next_offset,
                    pe=pe,
                    insts=insts,
                    ifrom=insts[inst.offset],
                    from_pred=True,
                    verbose=verbose
                )

                if remote_offset:
                    insts = _dis(
                        data=data,
                        offset=remote_offset,
                        pe=pe,
                        insts=insts,
                        ifrom=insts[inst.offset],
                        from_pred=False,
                        verbose=verbose
                    )

            # 1 child (next) - basic instruction
            else:
                next_offset = inst.offset + inst.size
                insts = _dis(
                    data=data,
                    offset=next_offset,
                    pe=pe,
                    insts=insts,
                    ifrom=insts[inst.offset],
                    from_pred=True,
                    verbose=verbose
                )

            return insts

        insts = _dis(data=data, offset=offset, pe=pe, insts=insts, verbose=verbose)

        # Exploration of the exported functions
        _dis_exported_funcs(pe=pe, insts=insts, data=data, verbose=verbose)

        # Search for unrecognized functions from their prolog function
        prologues_re = "|".join(self.prologues)
        compiled_re = re.compile(prologues_re)
        for m in compiled_re.finditer(data):
            function_offset = m.start()

            if function_offset not in insts:
                insts = _dis(data=data, offset=function_offset, pe=pe, insts=insts, verbose=verbose)
        return insts

    def display(self, insts, offset_from=0):
        for offset, inst in sorted(insts.iteritems()):
            if offset >= offset_from:
                print inst

    def export_to_dot(self, insts, oep_offset, displayable=True):
        '''
            Export the intruction graph to .dot format
        '''
        nodes = StringIO()
        edges = StringIO()
        dot = StringIO()

        header = "digraph G {\n"
        footer = "}"

        if displayable:

            for offset, inst in sorted(insts.iteritems()):
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


class ELFDisassembler:
    def __init__(self, arch, mode):
        self.arch = arch
        self.mode = mode
        self.capstone = Cs(self.arch, self.mode)

        self.prologues = {
            CS_MODE_32: [
                "\x55\x89\xE5",  # push ebp & mov ebp, esp
                "\x55\x8B\xEC",  # push ebp & mov ebp, esp
            ],
            CS_MODE_64: [
                "\x55\x48\x89\xE5",  # push rbp & mov rbp, rsp
            ]
        }[mode]

    def get_offset_from_rva(self, elf, rva):
        for segment in elf.iter_segments():
            if segment['p_vaddr'] <= rva < segment['p_vaddr'] + segment['p_memsz']:
                return segment['p_offset'] + (rva - segment['p_vaddr'])
        return None

    def get_rva_from_offset(self, elf, offset):
        for segment in elf.iter_segments():
            if segment['p_offset'] <= offset < segment['p_offset'] + segment['p_filesz']:
                return segment['p_vaddr'] + (offset - segment['p_offset'])
        return None

    def get_image_base_rva(self, elf):
        for section in elf.iter_sections():
            return section['sh_addr'] - section['sh_offset']
        return None

    def dis(self, data, offset, iat_api, elf, verbose=False):
        '''
            data: raw binary of full elf
            va: va of the instruction located at <data[index]>
            iat_api: dict of imported API like {VA_IN_IAT: API_NAME}

        '''
        insts = dict()

        def _dis_exported_funcs(elf, insts, verbose):
            """
            Disassemble all the exported functions.

            Args:
                elf (ELFFile) : ELF Object
                insts (Dict)  : Dictionary of instructions
            """
            image_base = self.get_image_base_rva(elf)

            if elf.get_section_by_name('.dynsym') is not None:
                # Dynsym
                for sym in elf.get_section_by_name('.dynsym').iter_symbols():

                    info = sym.entry

                    # If the symbol is an exported function
                    if info.st_info['type'] == 'STT_FUNC' and \
                       info.st_info['bind'] == 'STB_GLOBAL':

                        # If this is a new non-empty function
                        if info.st_value != 0 and info.st_value not in insts:

                            offset = self.get_offset_from_rva(
                                elf,
                                (info.st_value - image_base)
                            )

                            if verbose:
                                print 'Func %s found at offset 0x%08X, RVA: 0x%08X' % (
                                    sym.name,
                                    offset,
                                    info.st_value
                                )

                            insts = _dis(data=data,
                                         offset=offset,
                                         elf=elf,
                                         insts=insts,
                                         verbose=verbose)

        def _dis(data, offset, insts, elf, ifrom=None, verbose=False, from_pred=True):
            '''
                <insts> is a dict like {'offset': <Instruction>}
            '''

            if offset is None:
                return insts

            if offset in insts:
                if ifrom:
                    insts[offset].add_ifrom(ifrom.offset)
                    insts[ifrom.offset].add_ito(insts[offset].offset, from_pred)
                return insts

            rva = self.get_rva_from_offset(elf, offset)
            if rva is None:
                if verbose:
                    print "Offset " + hex(offset) + " not found in segments: discarded."
                return insts

            image_base = self.get_image_base_rva(elf)
            inst_va = rva + image_base

            try:
                i = self.capstone.disasm(data[offset:], inst_va, count=1).next()
            except:
                return insts

            inst = Instruction(
                id=i.id,
                offset=offset,
                va=inst_va,
                address=i.address,
                mnemonic=i.mnemonic,
                op_str=i.op_str,
                size=i.size,
                bytes=i.bytes,
            )
            insts[inst.offset] = inst

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
                        remote_offset = self.get_offset_from_rva(
                            elf,
                            int(inst.op_str, 16) - self.get_image_base_rva(elf))
                        insts = _dis(
                            data=data,
                            offset=remote_offset,
                            elf=elf,
                            insts=insts,
                            ifrom=insts[inst.offset],
                            from_pred=False,
                            verbose=verbose
                        )
                    except:
                        pass

            # 2 children (next, then remote) - except call
            elif inst.mnemonic in [
                    'jz', 'je', 'jcxz', 'jecxz', 'jrcxz', 'jnz', 'jp', 'jpe', 'jnp', 'ja', 'jae', 'jb', 'jbe',
                    'jg', 'jge', 'jl', 'jle', 'js', 'jns', 'jo', 'jno', 'jecxz', 'loop', 'loopne', 'loope',
                    'jne']:
                next_offset = inst.offset + inst.size
                remote_offset = self.get_offset_from_rva(elf, int(inst.op_str, 16) - self.get_image_base_rva(elf))

                # inst.next.append(next_offset)
                # inst.next.append(remote_offset)
                # print inst

                insts = _dis(
                    data=data,
                    offset=next_offset,
                    elf=elf,
                    insts=insts,
                    ifrom=insts[inst.offset],
                    from_pred=True,
                    verbose=verbose
                )

                insts = _dis(
                    data=data,
                    offset=remote_offset,
                    elf=elf,
                    insts=insts,
                    ifrom=insts[inst.offset],
                    from_pred=False,
                    verbose=verbose
                )

            # 2 children (next, then remote) - call
            elif inst.mnemonic in ['call']:

                next_offset = inst.offset + inst.size
                remote_offset = None

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
                        remote_offset = self.get_offset_from_rva(
                            elf,
                            int(inst.op_str, 16) - self.get_image_base_rva(elf))
                    except Exception as e:
                        # print "ERROR CALL: %s\n%s\n" % (e, inst)
                        pass

                insts = _dis(
                    data=data,
                    offset=next_offset,
                    elf=elf,
                    insts=insts,
                    ifrom=insts[inst.offset],
                    from_pred=True,
                    verbose=verbose
                )

                if remote_offset:
                    insts = _dis(
                        data=data,
                        offset=remote_offset,
                        elf=elf,
                        insts=insts,
                        ifrom=insts[inst.offset],
                        from_pred=False,
                        verbose=verbose
                    )

            # 1 child (next) - basic instruction
            else:
                next_offset = inst.offset + inst.size
                # inst.next.append(next_offset)
                # print inst
                insts = _dis(
                    data=data,
                    offset=next_offset,
                    elf=elf,
                    insts=insts,
                    ifrom=insts[inst.offset],
                    from_pred=True,
                    verbose=verbose
                )

            return insts

        insts = _dis(data=data, offset=offset, elf=elf, insts=insts, verbose=verbose)

        # Function 'start' jumps on function 'main' with a dynamic jump. 'main' address is given in argument
        # so we get that argument and we continue to disassemble
        '''
        .text:0000000000XXX89F                 mov     r8, offset fini ; fini
        .text:0000000000XXX8A6                 mov     rcx, offset init ; init
        .text:0000000000XXX8AD                 mov     rdi, offset main ; main
        .text:0000000000XXX8B4                 call    ___libc_start_main
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

            if i1.mnemonic != "mov" or i2.mnemonic != "mov" or i3.mnemonic != "mov" or i4.mnemonic != "call":
                continue

            try:
                rva_fini = int(i1.op_str.split(", 0x")[1], 16)
                rva_init = int(i2.op_str.split(", 0x")[1], 16)
                rva_main = int(i3.op_str.split(", 0x")[1], 16)

                insts = _dis(data=data, offset=self.get_offset_from_rva(elf, rva_fini), elf=elf, insts=insts, verbose=verbose)
                insts = _dis(data=data, offset=self.get_offset_from_rva(elf, rva_init), elf=elf, insts=insts, verbose=verbose)
                insts = _dis(data=data, offset=self.get_offset_from_rva(elf, rva_main), elf=elf, insts=insts, verbose=verbose)

                break
            except:
                continue

        # Exploration of the exported functions
        _dis_exported_funcs(elf=elf, insts=insts, verbose=verbose)

        # Search for unrecognized functions from their prolog function
        for prologue in self.prologues:
            for m in re.finditer(prologue, data):

                function_offset = m.start()

                if function_offset not in insts:
                    insts = _dis(data=data, offset=function_offset, elf=elf, insts=insts, verbose=verbose)

        return insts

    def display(self, insts, offset_from=0):
        for offset, inst in sorted(insts.iteritems()):
            if offset >= offset_from:
                print inst

    def export_to_dot(self, insts, oep_offset, displayable=True):
        '''
            Export the intruction graph to .dot format
        '''
        nodes = StringIO()
        edges = StringIO()
        dot = StringIO()

        header = "digraph G {\n"
        footer = "}"

        if displayable:
            for offset, inst in sorted(insts.iteritems()):
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


def disassemble_pe(pe_data = None, pe_path = None, dot_path = None, print_listing=False, readable=False, verbose=False):
    if pe_data is None and pe_path is None:
        print "ERROR: missing PE path or data."
        return None

    if pe_data is None:
        pe_data = open(pe_path, "r").read()

    try:
        pe = pefile.PE(pe_path)
    except:
        print "ERROR: pefile could not parse PE."
        return None

    def find_entry_point_section(pe, eop_rva):
        for section in pe.sections:
            if section.contains_rva(eop_rva):
                return section

        return None

    arch = CS_ARCH_X86
    is_32 = pe.FILE_HEADER.Characteristics & 0x0100
    mode = CS_MODE_32 if is_32 else CS_MODE_64

    oep_rva = pe.OPTIONAL_HEADER.AddressOfEntryPoint
    code_section = pe.get_section_by_rva(oep_rva)
    oep_offset = oep_rva - code_section.VirtualAddress + code_section.PointerToRawData

    iat_dict = dict()

    try:
        import_table = pe.DIRECTORY_ENTRY_IMPORT.symbols
    except:
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
    insts = disass.dis(data=pe_data, offset=oep_offset, iat_api=iat_dict, pe=pe, verbose=verbose)

    if dot_path is not None:
        dot = disass.export_to_dot(insts=insts, oep_offset=oep_offset, displayable=readable)
        open(dot_path, "wb").write(dot)

    if print_listing:
        disass.display(insts, offset_from=0)

    return True


def disassemble_elf(elf_data = None, elf_path = None, dot_path = None, print_listing=False, readable=False, verbose=False):
    if elf_path is None:
        print "ERROR: missing ELF path."
        return None

    if elf_data is None:
        elf_data = open(elf_path, "r").read()

    from elftools.elf.elffile import ELFFile
    elf = ELFFile(open(elf_path, "r"))

    arch = CS_ARCH_X86
    mode = CS_MODE_64 if elf.elfclass == 64 else CS_MODE_32

    oep_rva = elf.header.e_entry

    def get_offset_from_rva(elf, offset):
        for section in elf.iter_sections():
            try:
                if section['sh_addr'] <= oep_rva < section['sh_addr'] + section['sh_size']:
                    return section['sh_offset'] + (oep_rva - section['sh_addr'])
            except Exception as e:
                print e
                continue
        return None

    oep_offset = get_offset_from_rva(elf, oep_rva)

    if oep_offset is None:
        print "Cannot retrieve entry point offset from RVA (0x%08X), exiting." % (elf.header.e_entry)
        sys.exit(1)

    disass = ELFDisassembler(arch=arch, mode=mode)
    insts = disass.dis(data=elf_data, offset=oep_offset, iat_api={}, elf=elf, verbose=verbose)

    if dot_path is not None:
        dot = disass.export_to_dot(insts=insts, oep_offset=oep_offset, displayable=readable)
        open(dot_path, "w").write(dot)

    if print_listing:
        disass.display(insts, offset_from=0)

    return True


def disassemble_file(bin_data = None, bin_path=None, dot_path=None, print_listing=False, readable=False, verbose=False):
    if verbose:
        print "Disassembling", bin_path

    if bin_data is None:
        bin_data = open(bin_path, "rb").read()

    if bin_data[0:2] == "MZ":
        if disassemble_pe(pe_data=bin_data, pe_path=bin_path, dot_path=dot_path, print_listing=print_listing,
                          readable=readable, verbose=verbose):
            return dot_path
    elif bin_data[0:4] == "\x7fELF":
        if disassemble_elf(elf_data=bin_data, elf_path=bin_path, dot_path=dot_path, print_listing=print_listing,
                           readable=readable, verbose=verbose):
            return dot_path
    else:
        if verbose:
            print("WARNING: Test file " + bin_path + " does not seem to be a PE/ELF or dot file.")
        return None


def disas_worker(arg):
    disassemble_file(bin_path=arg[0], dot_path=arg[1], print_listing=arg[2], readable=arg[3], verbose=arg[4])


def disassemble_files(path_list, dot_path_suffix, multiprocess=True, n_processes=1, print_listing=False, readable=False, verbose=False):
    dot_path_list = []
    arg_list = []

    if multiprocess:
        for path in path_list:
            arg_list.append((path, path + dot_path_suffix, print_listing, readable, verbose))

        original_sigint_handler = signal.signal(signal.SIGINT, signal.SIG_IGN)
        pool = multiprocessing.Pool(processes=n_processes)
        signal.signal(signal.SIGINT, original_sigint_handler)

        try:
            res = pool.map_async(disas_worker, arg_list)

            # without timeout (one year) SIGINT is ignored
            res.get(timeout=31536000)
        except KeyboardInterrupt:
            pool.terminate()
        else:
            pool.close()

        for path in path_list:
            dot_path = path + dot_path_suffix
            if os.path.isfile(dot_path):
                dot_path_list.append(dot_path)
    else:
        for path in path_list:
            r = disassemble_file(bin_path=path, dot_path=path+dot_path_suffix, print_listing=print_listing,
                                 readable=readable, verbose=verbose)
            if r is not None:
                dot_path_list.append(r)

    return dot_path_list



