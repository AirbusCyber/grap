#!/usr/bin/env python
import sys
import os
from pygrap import *
from grap_disassembler import disassembler
import pefile

def main():
    if len(sys.argv) <= 1:
        print "error: Need one file to analyze."
        sys.exit(1)

    bin_path = sys.argv[1]
    dot_path = sys.argv[1] + ".dot"

    if not os.path.isfile(dot_path):
        disassembler.disassemble_file(bin_path=bin_path, dot_path=dot_path)

    test_graph = getGraphFromPath(dot_path)

    print "Analyzing", bin_path

    if not os.path.isfile(bin_path) or not os.path.isfile(dot_path):
        print "Error: binary or dot file doesn't exist, exiting."
        sys.exit(1)

    pattern_decrypt = "backspace_decrypt_algos.dot"
    matches_decrypt = match_graph(pattern_decrypt, test_graph)

    if len(matches_decrypt) >= 2:
        print "Error: two or more decryption algorithms matched, exiting."
        sys.exit(1)

    for algorithm_name in matches_decrypt:
        print "Matched algorithm:", algorithm_name

        first_match = matches_decrypt[algorithm_name][0]
        first_group = first_match["A"]
        first_instruction = first_group[0]
        description = first_instruction.info.inst_str
        address = first_instruction.info.address
        print "First matched subgraph got as A instruction:", "\"" + description + "\"", "at", hex(int(address))

        # Find the beginning of the function:
        # It is a node with at least 5 fathers which address a fulfills: address - 30 <= a <= address
        address_cond = "address >= " + str(hex(int(address - 30))) + " and address <= " + str(hex(int(address)))
        entrypoint_pattern = """
        digraph decrypt_fun_begin{
            ep [label="ep", cond="nfathers >= 5 and FILL_ADDR_COND", getid="ep"]
        }
        """.replace("FILL_ADDR_COND", address_cond)

        matches_entrypoint = match_graph(entrypoint_pattern, test_graph)

        if len(matches_entrypoint) != 1 or len(matches_entrypoint["decrypt_fun_begin"]) != 1:
            print "Error: Entrypoint not found, exiting"
            sys.exit(1)

        entrypoint = hex(int(matches_entrypoint["decrypt_fun_begin"][0]["ep"][0].info.address))
        push_call_pattern = """
        digraph push_call_decrypt{
            push [label="push", cond="opcode is push", minrepeat=2, maxrepeat=5, getid=push]
            call [label="call", cond="opcode is call"]
            entrypoint [label="entrypoint", cond="address is FILL_ADDR"]

            push -> call
            call -> entrypoint [childnumber=2]
        }
        """.replace("FILL_ADDR", entrypoint)

        matches_calls = match_graph(push_call_pattern, test_graph)

        if len(matches_calls) == 0:
            print "error: No call found, exiting"
            sys.exit(1)

        print len(matches_calls["push_call_decrypt"]), "calls to decrypt function found."

        str_tuple = []
        for m in matches_calls["push_call_decrypt"]:
            # Work on matches with immediate arguments such as:
            # PUSH (between 2 and 5) with hex arguments (for instance: 9, 0x12 or 0x4012a3)
            # CALL entrypoint
            if len(m["push"][-2].info.arg1) == 1 or "0x" in m["push"][-2].info.arg1:
                str_tuple.append((int(m["push"][-2].info.arg1, 16), int(m["push"][-1].info.arg1, 16)))

        decrypted_strings = decrypt_strings(algorithm_name, str_tuple, bin_path)

        print "\nDecrypted strings:"
        for d in decrypted_strings:
            print d

    graph_free(test_graph, True)


def decrypt_xor_sub(s):
    out = ""
    for c in s:
        o = ord(c)
        o = o ^ 0x11
        o = o - 0x25
        out += chr(o % 0x100)
    return out


def decrypt_sub_xor_sub(s):
    out = ""
    cl = 0
    for c in s:
        o = ord(c)
        o -= cl
        o = o ^ 0x0b
        o = o - 0x12
        out += chr(o % 0x100)
        cl += 1
    return out


def decrypt_sub_add(s):
    out = ""
    cl = 0
    for c in s:
        o = ord(c)
        dl = 0xff
        dl -= cl
        o += dl
        out += chr(o % 0x100)
        cl += 1
    return out


def decrypt_xor_sub_sub(s):
    out = ""
    i = 0
    for c in s:
        o = ord(c)
        o = o ^ 0x17
        o = o - i
        o = o - 0x0b
        out += chr(o % 0x100)
        i += 1
    return out


def decrypt_sub_xor_add(s):
    out = ""
    i = 0
    for c in s:
        o = ord(c)
        o = o - i
        o = o ^ 0x19
        o = o + 0x13
        out += chr(o % 0x100)
        i += 1
    return out


def decrypt_str(d, algo):
    if algo == "decrypt_xor_sub":
        return decrypt_xor_sub(d)
    elif algo == "decrypt_sub_xor_sub":
        return decrypt_sub_xor_sub(d)
    elif algo == "decrypt_sub_add1":
        return decrypt_sub_add(d)
    elif algo == "decrypt_sub_add2":
        return decrypt_sub_add(d)
    elif algo == "decrypt_xor_sub_sub":
        return decrypt_xor_sub_sub(d)
    elif algo == "decrypt_sub_xor_add":
        return decrypt_sub_xor_add(d)
    else:
        print "warning: unknown algo", algo
        return None


def decrypt_strings(algo, str_tuple, bin_path):
    try:
        data = open(bin_path, "rb").read()
        pe = pefile.PE(data=data)
        base_addr = pe.OPTIONAL_HEADER.ImageBase
    except:
        print "error: pefile"
        sys.exit(1)

    decrypted = []
    for size, addr in str_tuple:
        d = pe.get_data(addr - base_addr, size)
        decrypted_str = decrypt_str(d, algo)
        if decrypted_str is not None:
            decrypted.append(decrypted_str)

    return decrypted


if __name__ == '__main__':
    main()
    sys.exit(0)
