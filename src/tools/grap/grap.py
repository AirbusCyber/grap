#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import pygrap
import subprocess
import os
import sys
import argparse

GRAP_VERSION="1.0.0"

def main():
    sys.setrecursionlimit(1000000)

    parser = argparse.ArgumentParser(description='grap: look for a graph pattern in a PE/ELF/RAW binary or a .dot graph file',
                                     formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--version', action='version', version=GRAP_VERSION)

    parser.add_argument(dest='pattern',  help='Pattern file (.dot) to look for')
    parser.add_argument(dest='test', nargs="+", help='Test file(s) to analyse')

    parser.add_argument('-r', '--recursive', dest='recursive', action="store_true", default=False, help='Analyzes test files recursively (test must be a directory)')
    parser.add_argument('-f', '--force', dest='force', action="store_true", default=False, help='Force re-generation of existing .dot file')
    parser.add_argument('--raw', dest='raw_disas', action="store_true", default=False, help='Disassemble raw file')
    parser.add_argument('-r64', '--raw-64', dest='raw_64', action="store_true", default=False, help='Disassemble raw file with x86_64 (not default)')
    parser.add_argument('-od', '--only-disassemble', dest='only_disassemble', action="store_true", default=False, help='Disassemble files and exit (no matching)')
    parser.add_argument('-o', '--dot-output', dest='dot', help='Specify exported DOT file name (when there is only one test file) or directory')
    parser.add_argument('-er', '--readable', dest='readable', action="store_true", default=False, help='Export .dot in displayable format (with xdot)')
    parser.add_argument('-nt', '--no-threads', dest='multithread', action="store_false", default=True, help='No multiprocesses nor multithreads')
    parser.add_argument('-m', '--print-all-matches', dest='print_all_matches', action="store_true", default=False, help='Print all matched nodes (overrides getid fields)')
    parser.add_argument('-nm', '--print-no-matches', dest='print_no_matches', action="store_true", default=False, help='Don\'t print matched nodes (overrides getid fields)')
    parser.add_argument('-sa', '--show-all', dest='show_all', action="store_true", default=False, help='Show all tested (including not matching) files (not default when quiet, default otherwise)')
    parser.add_argument('-b', '--grap-match-path', dest='grap_match_path', help='Specify the path of the grap-match binary (default: /usr/local/bin/grap-match)')
    parser.add_argument('-t', '--timeout', dest='timeout', default=120, help='Specify timeout (in seconds) for disassembly, assign 0 for no timeout (default: 120)')
    parser.add_argument('-q', '--quiet', dest='quiet', action="store_true", default=False, help='Quiet output: one file per line with the number of disassembled instruction and matches')
    parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", default=False, help='Verbose output')
    parser.add_argument('-d', '--debug', dest='debug', action="store_true", default=False, help='Debug output')
    parser.add_argument('-p', '--pattern', dest='pattern_path', action="append", nargs=1, help='Include additional pattern file, can be used multiple times')
    args = parser.parse_args()

    printed_something = False

    if args.pattern is None or args.test is None:
        sys.exit(0)

    test_paths = []
    dot_test_files = set()
    for test_path in args.test:
        if os.path.isdir(test_path):
            if args.recursive:
                dot_test_files.add(test_path)
                test_paths += list_files_recursively(test_path)
        else:
            test_paths.append((test_path, None))

    files_to_disassemble = set()
    for test_path, dir_arg_path in test_paths:
        try:
            f = open(test_path, "rb")
            data = f.read(7)
            f.close()
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
                if dir_arg_path is None:
                    dot_test_files.add(test_path)
            else:
                if args.dot is None:
                    dot_path = test_path + ".grapcfg"
                else:
                    if os.path.isdir(args.dot):
                        dot_path = os.path.join(args.dot, os.path.basename(test_path) + ".grapcfg")
                    else:
                        dot_path = args.dot

                if os.path.exists(dot_path) and not args.force:
                    if args.verbose:
                        print("Skipping generation of existing " + dot_path)
                        printed_something = True
                    if dir_arg_path is None:
                        dot_test_files.add(dot_path)
                else:
                    if len(args.test) == 1 and args.dot is not None:
                        found_path = pygrap.disassemble_file(bin_path=test_path, dot_path=dot_path,
                                                                   readable=args.readable, verbose=args.verbose,
                                                                   raw=args.raw_disas, raw_64=args.raw_64)
                        if found_path is not None:
                            dot_test_files.add(dot_path)
                    else:
                        files_to_disassemble.add((test_path, dir_arg_path))

    if len(test_paths) > 1 or args.dot is None:
        if args.dot is not None and not os.path.isdir(args.dot):
            print "ERROR: With multiple files to analyze, DOT path (option -o or or --dot-output) must be a directory."
            sys.exit(0)

        files_to_disassemble = sorted(list(files_to_disassemble), key=lambda tup: tup[0])
        disassembled_files = pygrap.disassemble_files(files_to_disassemble, ".grapcfg", dot_dir=args.dot, multiprocess=args.multithread,
                                                            n_processes=4, readable=args.readable, verbose=args.verbose,
                                                            raw=args.raw_disas, raw_64=args.raw_64, timeout=args.timeout)
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

            if not args.grap_match_path:
                command = ["/usr/local/bin/grap-match"]
            else:
                command = [args.grap_match_path]

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

            if args.recursive:
                command.append("-r")

            if args.pattern_path is not None:
                for p in args.pattern_path:
                    command.append("-p")
                    command.append(p[0])

            command.append(pattern_path)

            for test_path in dot_test_files:
                command.append(test_path)

            if args.verbose or args.debug:
                print(" ".join(command))

            sys.stdout.flush()
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


def list_files_recursively(path, option_filter=False, extension_filter=""):
    paths = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if not option_filter or name.endswith(extension_filter):
                paths.append((os.path.join(root, name), path))
    return paths


if __name__ == '__main__':
    main()


