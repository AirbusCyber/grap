#!/usr/bin/python2
# -*- coding: utf-8 -*-

import re
import sys
from core.pe import PE
from capstone import Cs
from capstone import CS_ARCH_X86
from capstone import CS_MODE_32
from capstone import CS_MODE_64
from cStringIO import StringIO
from pandape.tools.config import *
from pandape.tools.disassembler import *
import subprocess
import os

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='grap: look for pattern in a PE/ELF binary or a .dot graph file')
    parser.add_argument('-p', '--pattern', dest='pattern', help='Pattern file (.dot) to look for')
    # parser.add_argument(dest='pattern', help='Pattern file (.dot) to look for')
    parser.add_argument('-w', '--wexe', help='Windows Executable File (PE)')
    parser.add_argument('-l', '--lexe', help='Linux Executable File (ELF)')

    parser.add_argument('-f', '--force', dest='force', action="store_true", help='Force re-generation of existing .dot file')
    parser.add_argument('-t', '--dot-path', dest='dot', help='Specify exported .dot file name')
    # parser.add_argument(dest='dot', help='Specify exported .dot file name')
    parser.add_argument('-r', '--readable', dest='readable', action="store_true", help='DOT in human-readable format')
    parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", help='Verbose output')
    parser.add_argument('-d', '--debug', dest='debug', action="store_true", help='Debug output')
    parser.add_argument('-q', '--quiet', dest='quiet', action="store_true", help='Quiet output')
    args = parser.parse_args()

    parsed_binary = False

    if args.wexe is None and args.lexe is None and args.dot is None:
        sys.exit(0)

    if args.dot is None:
        if args.wexe:
            fpath = args.wexe
        elif args.lexe:
            fpath = args.lexe

        dotpath = fpath + ".dot"
    else:
        dotpath = args.dot

    if os.path.exists(dotpath) and not args.force:
        if args.verbose:
            print("Skipping generation of existing " + dotpath)
    else:
        if args.wexe is not None:
            data = open(args.wexe, "r").read()
            pe = PE(raw_data=data)

            arch = CS_ARCH_X86
            mode = CS_MODE_32 if pe.is_32bits() else CS_MODE_64
            oep = pe.get_entry_point_offset()

            iat_dict = pe.get_iat_api()

            disass = PEDisassembler(arch=arch, mode=mode)
            insts = disass.dis(data=data, offset=oep, iat_api=iat_dict, pe=pe)

            dot = disass.export_to_dot(insts=insts, oep_offset=oep, displayable=args.readable)
            open(dotpath, "w").write(dot)
            parsed_binary = True

        elif args.lexe is not None:
            from elftools.elf.elffile import ELFFile
            elf = ELFFile(open(args.lexe, "r"))
            data = open(args.lexe, "r").read()

            arch = CS_ARCH_X86
            mode = CS_MODE_64 if elf.elfclass == 64 else CS_MODE_32

            oep_rva = elf.header.e_entry
            oep_offset = None

            def get_offset_from_rva(elf, offset):
                for section in elf.iter_sections():
                    try:
                        if section['sh_addr'] <= oep_rva < section['sh_addr'] + section['sh_size']:
                            return section['sh_offset'] + (oep_rva - section['sh_addr'])
                    except Exception as e:
                        print(e)
                        continue
                return None

            oep_offset = get_offset_from_rva(elf, oep_rva)

            if oep_offset is None:
                print("Cannot retrieve entry point offset from RVA (0x%08X)" % (elf.header.e_entry))
                sys.exit(0)

            disass = ELFDisassembler(arch=arch, mode=mode)
            insts = disass.dis(data=data, offset=oep_offset, iat_api={}, elf=elf)

            dot = disass.export_to_dot(insts=insts, oep_offset=oep_offset, displayable=args.readable)
            open(dotpath, "w").write(dot)
            parsed_binary = True

    if args.pattern is not None:
        if args.verbose:
            verbose = "-v"
        else:
            verbose = ""

        if args.debug:
            debug = "-d"
        else:
            debug = ""

        if args.quiet:
            quiet = "-q"
        else:
            quiet = ""

        if parsed_binary:
            print("")
        command = ("/usr/local/bin/grap-match", args.pattern, dotpath, verbose, debug, quiet)
        popen = subprocess.Popen(command)
        popen.wait()

