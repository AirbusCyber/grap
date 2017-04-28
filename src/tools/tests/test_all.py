#!/usr/bin/env python
import sys
import os
import subprocess
import tempfile
from pygrap import *
from grap_disassembler import disassembler

Red = "\x1b[1;31m";
Green = "\x1b[1;32m";
Blue = "\x1b[1;33m";
Color_Off = "\x1b[0m";


def main():
    test_dir = find_test_dir(sys.argv)
    if test_dir is None:
        print "Test graphs not found in directory"
        return 1

    n_tests, expected, pattern_paths, test_paths, bin_paths, wildcards = parse_tests(test_dir)
    if n_tests == 0:
        print "No test found in directory " + test_dir
        return 1

    verbose = False
    for v in sys.argv:
        if v == "-v" or v == "--verbose":
            verbose = True

    if verbose:
        print Blue + "Testing ./tests", Color_Off
        sys.stdout.flush()
    error_tests = test_tests(verbose, "./tests")
    print_error_msg(error_tests, "./tests: " + str(error_tests) + " error(s) found.")

    if verbose:
        print ""
        print Blue + "Testing ./grap-match", Color_Off
    error_gm = test_grap_match_binary(verbose, None, "./grap-match", n_tests, expected, pattern_paths, test_paths, wildcards)
    print_error_msg(error_gm, "./grap-match: " + str(error_gm) + " error(s) found.")

    if verbose:
        print ""
        print Blue + "Testing ./grap-match.py", Color_Off
    error_gmpy = test_grap_match_binary(verbose, "python2", "./grap-match.py", n_tests, expected, pattern_paths, test_paths, wildcards)
    print_error_msg(error_gmpy, "./grap-match.py: " + str(error_gmpy) + " error(s) found.")

    if verbose:
        print ""
        print Blue + "Testing python bindings with disassembler bindings and grap when binary is present", Color_Off
    error_bindings = test_bindings(verbose, n_tests, expected, pattern_paths, test_paths, bin_paths, wildcards)
    print_error_msg(error_gmpy, "Disassembler + python bindings: " + str(error_gmpy) + " error(s) found.")

    error_total = error_tests + error_gm + error_gmpy + error_bindings

    if verbose:
        print ""

    print_error_msg(error_total, "Total: " + str(error_total) + " error(s) found.")

    if error_total > 255:
        sys.exit(255)
    else:
        sys.exit(error_total)


def print_error_msg(error_count, message):
    if error_count == 0:
        color = Green
    else:
        color = Red
    print color + message + Color_Off


def test_tests(verbose, program):
    command = [program]

    if verbose:
        process = subprocess.Popen(command)
    else:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    process.communicate()
    exitcode = process.returncode

    return exitcode


def test_grap_match_binary(verbose, interpreter, program, n_tests, expected, pattern_paths, test_paths, wildcards):
    error_count = 0
    if not os.path.isfile(program):
        print program + " not found."
        return 1

    for i in range(n_tests):
        if i >= 1 and verbose:
            print ""

        args = []
        tmp_pattern = None

        if len(pattern_paths[i]) == 1:
            args += pattern_paths[i]
        else:
            tmp_pattern = tempfile.NamedTemporaryFile()
            for path in pattern_paths[i]:
                data = open(path, "r").read()
                tmp_pattern.file.write(data)
            tmp_pattern.file.flush()
            args.append(tmp_pattern.name)
        args.append(test_paths[i])

        multiple_patterns_in_dot = False
        if len(pattern_paths[i]) == 1:
            lines = open(pattern_paths[i][0], "r").read().split("\n")

            found_beginning = False
            for l in lines:
                if len(l) >= 9 and (l[0] == "D" or l[0] == "d") and l[1:7] == "igraph":
                    if l.rstrip()[-1] == "{":
                        if found_beginning:
                            multiple_patterns_in_dot = True
                            break
                        found_beginning = True

        launcher = []
        if interpreter is not None:
            launcher.append(interpreter)
        launcher.append(program)

        command_label_tree = launcher + [] + args
        command_label_singletraversal = launcher + ["--single-traversal"] + args
        command_nolabel_tree = launcher + ["--no-check-labels"] + args
        command_nolabel_singletraversal = launcher + ["--no-check-labels", "--single-traversal"] + args

        if verbose:
            print Blue + "Running test", i, Color_Off
            print "Checking labels:"
        sys.stdout.flush()
        error_count += run_and_parse_command(verbose, i, command_label_tree, expected[i][0], "tree")
        if len(pattern_paths[i]) == 1 and not multiple_patterns_in_dot and not wildcards[i]:
            error_count += run_and_parse_command(verbose, i, command_label_singletraversal, expected[i][0], "single traversal")

        if verbose:
            print "Not checking labels:"
        error_count += run_and_parse_command(verbose, i, command_nolabel_tree, expected[i][1], "tree")
        if len(pattern_paths[i]) == 1 and not multiple_patterns_in_dot and not wildcards[i]:
            error_count += run_and_parse_command(verbose, i, command_nolabel_singletraversal, expected[i][1], "single traversal")

        if tmp_pattern is not None:
            tmp_pattern.file.close()

    return error_count


def test_bindings(verbose, n_tests, expected, pattern_paths, test_paths, bin_paths, wildcards):
    error_count = 0

    for i in range(n_tests):
        if i >= 1 and verbose:
            print ""

        tmp_pattern = None
        if len(pattern_paths[i]) == 1:
            pattern_path = pattern_paths[i][0]
        else:
            tmp_pattern = tempfile.NamedTemporaryFile()
            for path in pattern_paths[i]:
                data = open(path, "r").read()
                tmp_pattern.file.write(data)
            tmp_pattern.file.flush()
            pattern_path = tmp_pattern.name
        test_path = test_paths[i]
        bin_path = bin_paths[i]
        expect = expected[i][0]

        if verbose:
            print Blue + "Running test", i, Color_Off
            print "Checking labels:"
        sys.stdout.flush()
        error_count += run_bindings_test(verbose, pattern_path, test_path, bin_path, expect, wildcards)

        if error_count != 0:
            return error_count

        if tmp_pattern is not None:
            tmp_pattern.file.close()

    return error_count


def run_bindings_test(verbose, pattern_path, test_path, bin_path, expect, wildcards):
    error_number = 0

    if bin_path is not None:
        tmp_test_grap = tempfile.NamedTemporaryFile()
        tmp_test_grap_path = tmp_test_grap.name
        tmp_test_grap.close()
        command = []
        command.append("grap")
        command.append("-od")
        command.append("-o")
        command.append(tmp_test_grap_path)
        command.append(pattern_path)
        command.append(bin_path)

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()

        if verbose and err != "":
            print err

        matches = match_graph(pattern_path, tmp_test_grap_path)
        found_traversals = count_matches(matches)
        if found_traversals < expect:
            print Red + str(found_traversals), "traversals possible in test graph (expected:", str(expect) + ")", Color_Off
            error_number += 1
        else:
            if verbose:
                print Green + str(found_traversals), "traversals possible in test graph (expected:", str(expect) + ")", Color_Off

    if bin_path is not None:
        tmp_test_bindings = tempfile.NamedTemporaryFile()
        disassembler.disassemble_file(bin_path=bin_path, dot_path=tmp_test_bindings.name)
        matches = match_graph(pattern_path, tmp_test_bindings.name)
        tmp_test_bindings.close()
    else:
        matches = match_graph(pattern_path, test_path)

    found_traversals = count_matches(matches)
    if found_traversals != expect:
        print Red + str(found_traversals), "traversals possible in test graph (expected:", str(expect) + ")", Color_Off
        error_number += 1
    else:
        if verbose:
            print Green + str(found_traversals), "traversals possible in test graph (expected:", str(expect) + ")", Color_Off

    return error_number


def count_matches(matches):
    if matches is None:
        return 0

    found_traversals = 0
    for pattern in matches:
        for _ in matches[pattern]:
            found_traversals += 1
    return found_traversals


def run_and_parse_command(verbose, i, command, expected_traversals, algo):
    if verbose:
        process = subprocess.Popen(command, stdout=subprocess.PIPE)
    else:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    out, err = process.communicate()
    exitcode = process.returncode

    if exitcode != 0:
        print Red + " ".join(command) + " failed:" + Color_Off
        if err is not None:
            print err
        print out
        return 1

    lines = out.split("\n")
    found_traversals = None
    for l in lines:
        splitted = l.split(" ")
        if len(splitted) >= 3 and splitted[1] == "traversal(s)" and splitted[2] == "possible":
            found_traversals = int(splitted[0])

    if found_traversals is None:
        if not verbose:
            print " ".join(command) + ":"
        print Red + "Error: could not parse grap-match output." + Color_Off
        return 1
    else:
        if expected_traversals != found_traversals:
            if not verbose:
                print " ".join(command) + ":"
            print Red + str(found_traversals), "traversals possible in test graph (expected:", str(expected_traversals) + ") with " + algo + ".", Color_Off

            if not verbose:
                print ""

            return 1
        else:
            if verbose:
                print Green + str(found_traversals), "traversals possible in test graph (expected:", str(expected_traversals) + ") with "+ algo + ".", Color_Off
    return 0


def parse_tests(test_dir):
    expected = dict()
    pattern_paths = dict()
    test_paths = dict()
    bin_paths = dict()
    wildcards = dict()

    n_tests = 0
    while True:
        path = test_dir + "/" + "test" + str(n_tests)
        if os.path.isdir(path):
            expected_path = path + "/" + "expected"
            test_path = path + "/" + "test.dot"
            bin_path = path + "/" + "test"
            wildcard_path = path + "/" + "wildcard"

            expected_list = []
            if os.path.isfile(expected_path):
                data = open(expected_path, "r").read()
                splitted = data.split("\n")

                if len(splitted) < 2:
                    break
                else:
                    expected_list.append(int(splitted[0]))
                    expected_list.append(int(splitted[1]))

            n_pattern = 0
            pattern_list = []
            while True:
                pattern_path = path + "/" + "pattern_" + str(n_pattern) + ".dot"
                if os.path.isfile(pattern_path):
                    pattern_list.append(pattern_path)
                    n_pattern += 1
                else:
                    break

            if os.path.isfile(test_path) and len(pattern_list) > 0:
                expected[n_tests] = expected_list
                test_paths[n_tests] = test_path
                pattern_paths[n_tests] = pattern_list

                if os.path.isfile(bin_path):
                    bin_paths[n_tests] = bin_path
                else:
                    bin_paths[n_tests] = None
            else:
                break

            if os.path.isfile(wildcard_path):
                wildcards[n_tests] = True
            else:
                wildcards[n_tests] = False

            n_tests += 1
        else:
          break

    return n_tests, expected, pattern_paths, test_paths, bin_paths, wildcards
  

def find_test_dir(args):
    possible_test_dirs = ["tests_graphs", "../tests_graphs" , "../src/tests_graphs", "src/tests_graphs"]

    if len(args) > 1:
        possible_test_dirs = [args[1]] + possible_test_dirs

    for path in possible_test_dirs:
        if os.path.isdir(path):
            return path

    return None

main()
