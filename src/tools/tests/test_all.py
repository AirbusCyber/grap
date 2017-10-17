#!/usr/bin/env python
import sys
import os
import subprocess
import tempfile
from pygrap import *

Red = "\x1b[1;31m";
Green = "\x1b[1;32m";
Blue = "\x1b[1;33m";
Color_Off = "\x1b[0m";
log_path = None

def print_and_log(s):
    global log_path

    print s
    if log_path is not None:
        with open(log_path, "a") as f:
            f.write(s+"\n")

def main():
    global Red, Green, Blue, Color_Off, log_path

    test_dir = find_test_dir(sys.argv)
    if test_dir is None:
        print_and_log("Test graphs not found in directory")
        return 1

    n_tests, expected, pattern_paths, test_paths, bin_paths, wildcards = parse_tests(test_dir)
    if n_tests == 0:
        print_and_log("No test found in directory " + test_dir)
        return 1

    tests_path = "./tests"
    grap_match_path = "./grap-match"
    grap_match_py_path = "./grap-match.py"
    grap_path = "grap"
    verbose = False
    option_nt = False
    for i in range(1, len(sys.argv)):
        v = sys.argv[i]
        if v == "-v" or v == "--verbose":
            verbose = True
        elif v == "-nc" or v == "--no-color":
            Red = "";
            Green = "";
            Blue = "";
            Color_Off = "";
        elif v == "-nt" or v == "--no-threads":
            option_nt = True
        elif v == "--log-path" or v == "-l" and i+1 < len(sys.argv):
            log_path = sys.argv[i+1]
            f=open(log_path, "w")
            f.write("")
            f.close()
            i += 1
        elif v == "--tests" or v == "-t" and i+1 < len(sys.argv):
            tests_path = sys.argv[i+1]
            i += 1
        elif v == "--grap-match" or v == "-gm" and i+1 < len(sys.argv):
            grap_match_path = sys.argv[i+1]
            i += 1
        elif v == "--grap-match-py" or v == "-gmpy" and i+1 < len(sys.argv):
            grap_match_py_path = sys.argv[i+1]
            i += 1
        elif v == "--grap" or v == "-g" and i+1 < len(sys.argv):
            grap_path = sys.argv[i+1]
            i += 1

    if verbose:
        print_and_log(Blue + "Testing " + tests_path + Color_Off)
        sys.stdout.flush()
    error_tests = test_tests(verbose, tests_path)
    print_error_msg(error_tests, tests_path + ": " + str(error_tests) + " error(s) found.")

    if verbose:
        print_and_log("")
        print_and_log(Blue + "Testing " + grap_match_path + Color_Off)
    error_gm = test_grap_match_binary(verbose, option_nt, None, grap_match_path, n_tests, expected, pattern_paths, test_paths, wildcards)
    print_error_msg(error_gm, grap_match_path + ": " + str(error_gm) + " error(s) found.")

    if verbose:
        print_and_log("")
        print_and_log(Blue + "Testing " + grap_match_py_path + Color_Off)
    error_gmpy = test_grap_match_binary(verbose, False, "python", grap_match_py_path, n_tests, expected, pattern_paths, test_paths, wildcards)
    print_error_msg(error_gmpy, grap_match_py_path + ": " + str(error_gmpy) + " error(s) found.")

    if verbose:
        print_and_log("")
        print_and_log(Blue + "Testing python bindings with disassembler bindings and grap when binary is present" + Color_Off)
    error_bindings = test_bindings(verbose, grap_path, n_tests, expected, pattern_paths, test_paths, bin_paths, wildcards)
    print_error_msg(error_bindings, "Disassembler + python bindings: " + str(error_bindings) + " error(s) found.")

    error_total = error_tests + error_gm + error_gmpy + error_bindings

    if verbose:
        print_and_log("")

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
    print_and_log(color + message + Color_Off)


def test_tests(verbose, program):
    command = [program]

    if verbose:
        process = subprocess.Popen(command)
    else:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    process.communicate()
    exitcode = process.returncode

    return exitcode


def test_grap_match_binary(verbose, option_nt, interpreter, program, n_tests, expected, pattern_paths, test_paths, wildcards):
    error_count = 0
    if not os.path.isfile(program):
        print_and_log(program + " not found.")
        return 1

    for i in range(n_tests):
        if i >= 1 and verbose:
            print_and_log("")

        args = []
        tmp_pattern = None

        if option_nt:
            args.append("-nt")

        if len(pattern_paths[i]) == 1:
            args += pattern_paths[i]
        else:
            tmp_pattern = tempfile.NamedTemporaryFile(delete=False)
            for path in pattern_paths[i]:
                data = open(path, "rb").read()
                tmp_pattern.file.write(data)
            tmp_pattern.file.flush()
            args.append(tmp_pattern.name)
        args.append(test_paths[i])

        multiple_patterns_in_dot = False
        if len(pattern_paths[i]) == 1:
            lines = open(pattern_paths[i][0], "rb").read().split("\n")

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
            print_and_log(Blue + "Running test " + str(i) + Color_Off)
            print_and_log("Checking labels:")
        sys.stdout.flush()
        error_count += run_and_parse_command(verbose, i, command_label_tree, expected[i][0], "tree")
        if len(pattern_paths[i]) == 1 and not multiple_patterns_in_dot and not wildcards[i]:
            error_count += run_and_parse_command(verbose, i, command_label_singletraversal, expected[i][0], "single traversal")

        if verbose:
            print_and_log("Not checking labels:")
        error_count += run_and_parse_command(verbose, i, command_nolabel_tree, expected[i][1], "tree")
        if len(pattern_paths[i]) == 1 and not multiple_patterns_in_dot and not wildcards[i]:
            error_count += run_and_parse_command(verbose, i, command_nolabel_singletraversal, expected[i][1], "single traversal")

        if tmp_pattern is not None:
            tmp_pattern.file.close()

    return error_count


def test_bindings(verbose, grap_path, n_tests, expected, pattern_paths, test_paths, bin_paths, wildcards):
    error_count = 0

    for i in range(n_tests):
        if i >= 1 and verbose:
            print_and_log("")

        tmp_pattern = None
        if len(pattern_paths[i]) == 1:
            pattern_path = pattern_paths[i][0]
        else:
            tmp_pattern = tempfile.NamedTemporaryFile(delete=False)
            for path in pattern_paths[i]:
                data = open(path, "rb").read()
                tmp_pattern.file.write(data)
            tmp_pattern.file.flush()
            pattern_path = tmp_pattern.name
        test_path = test_paths[i]
        bin_path = bin_paths[i]
        expect = expected[i][0]

        if verbose:
            print_and_log(Blue + "Running test " + str(i) + Color_Off)
            print_and_log("Checking labels:")
        sys.stdout.flush()
        error_count += run_bindings_test(verbose, grap_path, pattern_path, test_path, bin_path, expect, wildcards)

        if tmp_pattern is not None:
            tmp_pattern.file.close()

    return error_count


def run_bindings_test(verbose, grap_path, pattern_path, test_path, bin_path, expect, wildcards):
    error_number = 0

    if bin_path is not None:
        # Disassembling with grap (grap.py)

        tmp_test_grap = tempfile.NamedTemporaryFile()
        tmp_test_grap_path = tmp_test_grap.name
        tmp_test_grap.close()
        command = []
        if len(grap_path) >= 3:
            if grap_path[-3:] == ".py":
                command.append("python")
        command.append(grap_path)
        command.append("-od")
        command.append("-o")
        command.append(tmp_test_grap_path)
        command.append(pattern_path)
        command.append(bin_path)

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = process.communicate()

        if verbose and err != "":
            print_and_log(err)

        matches = match_graph(pattern_path, tmp_test_grap_path)
        found_traversals = count_matches(matches)
        if found_traversals < expect:
            print_and_log(Red + str(found_traversals) + " traversals possible in test binary disassembled with "+ grap_path + " (expected: "+ str(expect) + ")" + Color_Off)
            error_number += 1
        else:
            if verbose:
                print_and_log(Green + str(found_traversals) + " traversals possible in test binary disassembled with "+ grap_path + " (expected: "+ str(expect) + ")" + Color_Off)

    if bin_path is not None:
        # Disassembling with python bindings

        tmp_test_bindings = tempfile.NamedTemporaryFile()
        tmp_test_bindings_path=tmp_test_bindings.name
        tmp_test_bindings.close()

        disassemble_file(bin_path=bin_path, dot_path=tmp_test_bindings_path)
        matches = match_graph(pattern_path, tmp_test_bindings_path)
        found_traversals = count_matches(matches)
        test_ok = found_traversals >= expect
        text = "test binary disassembled with python bindings"
    else:
        matches = match_graph(pattern_path, test_path)
        found_traversals = count_matches(matches)
        test_ok = found_traversals == expect
        text = "test file"

    if not test_ok:
        print_and_log(Red + str(found_traversals) + " traversals possible in " + text + " (expected: " + str(expect) + ")" + Color_Off)
        error_number += 1
    else:
        if verbose:
            print_and_log(Green + str(found_traversals) + " traversals possible in " + text + " (expected: " + str(expect) + ")" + Color_Off)

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
        print_and_log(Red + " ".join(command) + " failed:" + Color_Off)
        if err is not None:
            print_and_log(err)
        print_and_log(out)
        return 1

    lines = out.split("\n")
    found_traversals = None
    for l in lines:
        splitted = l.split(" ")
        if len(splitted) >= 2 and (splitted[1] == "traversal(s)" or splitted[1] == "matches:" or splitted[1] == 'matche(s)' or splitted[1] == 'match'):
            found_traversals = int(splitted[0])
            break

    if found_traversals is None:
        if not verbose:
            print_and_log(" ".join(command) + ":")
        print_and_log(Red + "Error: could not parse grap-match output." + Color_Off)
        return 1
    else:
        if expected_traversals != found_traversals:
            if not verbose:
                print_and_log(" ".join(command) + ":")
            print_and_log(Red + str(found_traversals), "traversals possible in test graph (expected:", str(expected_traversals) + ") with " + algo + "." + Color_Off)

            if not verbose:
                print_and_log("")

            return 1
        else:
            if verbose:
                print_and_log(Green + str(found_traversals) + " traversals possible in test graph (expected: " + str(expected_traversals) + ") with "+ algo + "." + Color_Off)
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
                data = open(expected_path, "rb").read()
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
