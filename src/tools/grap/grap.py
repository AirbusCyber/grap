#!/usr/bin/env python2
# -*- coding: utf-8 -*-

from grap_disassembler import disassembler
import pygrap
import subprocess
import os
import sys
import argparse

GRAP_VERSION="1.0.0"

if __name__ == '__main__':
    sys.setrecursionlimit(1000000)

    parser = argparse.ArgumentParser(description='grap: look for a graph pattern in a PE/ELF binary or a .dot graph file',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--version', action='version', version=GRAP_VERSION)

    parser.add_argument(dest='pattern',  help='Pattern file (.dot) to look for')
    parser.add_argument(dest='test', nargs="+", help='Test file(s) to analyse')

    parser.add_argument('-f', '--force', dest='force', action="store_true", default=False, help='Force re-generation of existing .dot file')
    parser.add_argument('--raw', dest='raw_disas', action="store_true", default=False, help='Disassemble raw file')
    parser.add_argument('-r64', '--raw-64', dest='raw_64', action="store_true", default=False, help='Disassemble raw file with x86_64 (not default)')
    parser.add_argument('-od', '--only-disassemble', dest='only_disassemble', action="store_true", default=False, help='Disassemble files and exit (no matching)')
    parser.add_argument('-o', '--dot-output', dest='dot', help='Specify exported .dot file name (when there is only one test file)')
    parser.add_argument('-r', '--readable', dest='readable', action="store_true", default=False, help='Export .dot in displayable format (with xdot)')
    parser.add_argument('-nt', '--no-threads', dest='multithread', action="store_false", default=True, help='No multiprocesses nor multithreads')
    parser.add_argument('-m', '--print-all-matches', dest='print_all_matches', action="store_true", default=False, help='Print all matched nodes (overrides getid fields)')
    parser.add_argument('-nm', '--print-no-matches', dest='print_no_matches', action="store_true", default=False, help='Don\'t print matched nodes (overrides getid fields)')
    parser.add_argument('-sa', '--show-all', dest='show_all', action="store_true", default=False, help='Show all tested (including not matching) files (not default when quiet, default otherwise)')
    parser.add_argument('-q', '--quiet', dest='quiet', action="store_true", default=False, help='Quiet output')
    parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", default=False, help='Verbose output')
    parser.add_argument('-d', '--debug', dest='debug', action="store_true", default=False, help='Debug output')
    args = parser.parse_args()

    printed_something = False

    if args.pattern is None or args.test is None:
        sys.exit(0)

    if args.dot is not None and len(args.test) > 1:
        print("You can specify dot path only when there is one test file.")
        sys.exit(0)

    files_to_disassemble = set()
    dot_test_files = set()
    for test_path in args.test:
        try:
            data = open(test_path, "r").read()
        except IOError:
            if os.path.isdir(test_path):
                print("Skipping directory " + test_path)
            elif not os.path.isfile(test_path):
                print("Skipping " + test_path + " (not found).")
            continue

        if data is None:
            print("WARNING: Can't open test file " + test_path)
            continue
        else:
            if data[0:7].lower() == "digraph":
                dot_test_files.add(test_path)
            else:
                if args.dot is None:
                    dot_path = test_path + ".dot"
                else:
                    dot_path = args.dot

                if os.path.exists(dot_path) and not args.force:
                    if args.verbose:
                        print("Skipping generation of existing " + dot_path)
                        printed_something = True
                    dot_test_files.add(dot_path)
                else:
                    if len(args.test) == 1:
                        found_path = disassembler.disassemble_file(bin_path=test_path, dot_path=dot_path,
                                                                   readable=args.readable, verbose=args.verbose,
                                                                   raw=args.raw_disas, raw_64=args.raw_64)
                        if found_path is not None:
                            dot_test_files.add(dot_path)
                    else:
                        files_to_disassemble.add(test_path)

    if len(args.test) > 1:
        files_to_disassemble = sorted(list(files_to_disassemble))
        disassembled_files = disassembler.disassemble_files(files_to_disassemble, ".dot", multiprocess=args.multithread,
                                                            n_processes=4, readable=args.readable, verbose=args.verbose,
                                                            raw=args.raw_disas, raw_64=args.raw_64)
        for path in disassembled_files:
            dot_test_files.add(path)

    if args.pattern is None or os.path.exists(args.pattern):
        pattern_path = args.pattern
    else:
        pattern_path = pygrap.get_dot_path_from_string(args.pattern)

        if args.verbose:
            print "Inferred pattern path written:", pattern_path

    dot_test_files = sorted(list(dot_test_files))
    if not args.only_disassemble:
        if pattern_path is not None and len(dot_test_files) >= 1:
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

            if args.show_all:
                command.append("-sa")

            if not args.multithread:
                command.append("-nt")

            command.append(pattern_path)

            for test_path in dot_test_files:
                command.append(test_path)

            if args.verbose or args.debug:
                print(" ".join(command))

            process = subprocess.Popen(tuple(command))
            process.communicate()
            exitcode = process.returncode

            if exitcode != 0:
                if exitcode != 1:
                    print("An unexpected error occurred in grap-match, try running it directly:")
                    print(" ".join(command))
                    print("\"Bad system call\" would mean this is caused by seccomp terminating the program. You may want to disable seccomp (see README).")
                sys.exit(exitcode)
        else:
            if not args.quiet:
                print("Missing pattern or test file.")

