#!/usr/bin/python2
# -*- coding: utf-8 -*-

from pandape.tools.disassembler import *
import subprocess
import os

GRAP_VERSION="1.0.0"

if __name__ == '__main__':
    import argparse

    parser = argparse.ArgumentParser(description='grap: look for pattern in a PE/ELF binary or a .dot graph file')
    parser.add_argument('--version', action='version', version=GRAP_VERSION)

    parser.add_argument(dest='pattern', help='Pattern file (.dot) to look for')
    parser.add_argument(dest='test', nargs="+", help='Test file(s) to analyse')

    parser.add_argument('-f', '--force', dest='force', action="store_true", help='Force re-generation of existing .dot file')
    parser.add_argument('-o', '--dot-output', dest='dot', help='Specify exported .dot file name')
    parser.add_argument('-r', '--readable', dest='readable', action="store_true", help='DOT in displayable format (with xdot)')
    parser.add_argument('-od', '--only-disassemble', dest='only_disassemble', action="store_true", help='Disassemble files and exit (no matching)')
    parser.add_argument('-m', '--print-all-matches', dest='print_all_matches', action="store_true", help='Print all matched nodes (overrides getid fields)')
    parser.add_argument('-nm', '--print-no-matches', dest='print_no_matches', action="store_true", help='Don\'t print matched nodes (overrides getid fields)')
    parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", help='Verbose output')
    parser.add_argument('-d', '--debug', dest='debug', action="store_true", help='Debug output')
    parser.add_argument('-q', '--quiet', dest='quiet', action="store_true", help='Quiet output')
    args = parser.parse_args()


    printed_something = False

    if args.pattern is None or args.test is None:
        sys.exit(0)

    if args.dot is not None and len(args.test) > 1:
        print("You can specify dot path only when there is one test file.")
        sys.exit(0)

    dot_test_files = []
    for test_path in args.test:
        data = open(test_path, "r").read()
        if data is None:
            print("Can't open test file " + test_path)
            sys.exit(0)

        if data[0:7].lower() == "digraph":
            dot_test_files.append(test_path)
        else:
            if args.dot is None:
                dotpath = test_path + ".dot"
            else:
                dotpath = args.dot

            if os.path.exists(dotpath) and not args.force:
                if args.verbose:
                    print("Skipping generation of existing " + dotpath)
                    printed_something = True
                dot_test_files.append(dotpath)
            else:
                if data[0:2] == "MZ":
                    pe = PE(data=data)

                    arch = CS_ARCH_X86
                    mode = CS_MODE_32 if pe.is_32bits() else CS_MODE_64
                    oep = pe.get_entry_point_offset()

                    try:
                        iat_dict = pe.get_iat_api()
                        disass = PEDisassembler(arch=arch, mode=mode)
                        insts = disass.dis(data=data, offset=oep, iat_api=iat_dict, pe=pe, verbose=args.verbose)

                        dot = disass.export_to_dot(insts=insts, oep_offset=oep, displayable=args.readable)
                        open(dotpath, "w").write(dot)
                    except:
                        print("Error while disassembling " + test_path)
                        printed_something = True
                        continue

                    dot_test_files.append(dotpath)
                    parsed_binary = True
                elif data[0:4] == "\x7fELF":
                    from elftools.elf.elffile import ELFFile
                    elf = ELFFile(open(test_path, "r"))

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
                    insts = disass.dis(data=data, offset=oep_offset, iat_api={}, elf=elf, verbose=args.verbose)

                    dot = disass.export_to_dot(insts=insts, oep_offset=oep_offset, displayable=args.readable)
                    open(dotpath, "w").write(dot)

                    dot_test_files.append(dotpath)
                    parsed_binary = True
                else:
                    if args.verbose:
                        print("Test file " + test_path + " does not seem to be a PE/ELF or dot file.")
                        printed_something = True

    if not args.only_disassemble:
        if args.pattern is not None and len(dot_test_files) >= 1:
            if printed_something or args.verbose:
                print("")
            command = ["/usr/local/bin/grap-match"]

            if args.print_all_matches:
                command.append("-m")

            if args.print_no_matches:
                command.append("-nm")

            if args.verbose:
                command.append("-v")

            if args.debug:
                command.append("-d")

            if args.quiet:
                command.append("-q")

            command.append(args.pattern)

            for test_path in dot_test_files:
                command.append(test_path)

            if args.verbose or args.debug:
                print(" ".join(command))

            popen = subprocess.Popen(tuple(command))
            popen.wait()
        else:
            if not args.quiet:
                print("Missing pattern or test file.")

