#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
import re
import tempfile


class Node:
    math_operators = ["==", "!=", ">=", "<=", "<", ">"]
    text_operators = ["is", "contains", "beginswith", "regex"]
    def __init__(self, _id, _cond):
        self.id = _id
        self.cond = _cond

    def parse_cond(self, cond_str):
        re_math = re.compile("|".join(self.math_operators))
        matches_math = re_math.findall(cond_str)
        if len(matches_math) >= 1:
            return cond_str

        splitted = cond_str.split()
        if len(splitted) >= 3:
            compiled_re = re.compile("|".join(self.text_operators))
            matches = compiled_re.findall(cond_str)
            if len(matches) >= 1:
                return cond_str
        elif cond_str.lower() == "true" or cond_str == "*" or cond_str == "":
            return "true"

#       Will match regex with cond_str
        if len(cond_str) >= 1 and cond_str[0] == "'" and cond_str[-1] == "'":
            stripped_cond = cond_str[1:-1]
        else:
            stripped_cond = cond_str

        if len(stripped_cond) >= 2 and (stripped_cond[:2] == ".*" or stripped_cond[-2:] == ".*"):
            regex = stripped_cond
        else:
            regex = ".*" + stripped_cond + ".*"
        return "inst regex '" + regex + "'"

    def update_cond(self, cond_str):
        if cond_str is not None:
            if self.cond is not None:
                print "ERROR: redefining existing condition on node with id:", self.id
            else:
                self.cond = self.parse_cond(cond_str)


def write_dot(f, name, nodes, edges):
    f.write("digraph " + name + " {\n")
    
    for n in nodes:
        if n.cond is None:
            n.cond = "true"

        f.write("\""+str(n.id) + "\"")
        f.write(" [cond=\"" + str(n.cond) + "\"")
        f.write(", getid=\""+str(n.id)+"\"")
        f.write("]\n")

    for (n1, cn, n2) in edges:
        f.write("\"" + n1.id + "\"")
        f.write(" -> ")
        f.write("\"" + n2.id + "\"")
        if cn is not None:
            f.write(" [childnumber = " + str(cn) + "]")
        f.write("\n")

    f.write("}\n")


def convert_export_str_to_dot(str_in, dot_file, pattern_name):
    nodes = []
    nodes_dict = dict()
    edges = []
    next_node_number = 1
    terms = str_in.split(";")
    for t in terms:
        nodes_splitted = re.split('(-[1-2*?]?>)', t)
        
        last_node = None
        for n in range(0, len(nodes_splitted), 2):
            node_str = nodes_splitted[n].strip()

            node = None
            id_split = node_str.split(":")
            if len(id_split) >= 2:
                _id = id_split[0]
                cond_str = id_split[1]
            elif node_str.isdigit():
                _id = node_str
                cond_str = None
            else:
                if " " not in node_str and node_str in nodes_dict:
                    _id = node_str
                    cond_str = None
                else:
                    _id = str(next_node_number)
                    cond_str = node_str

            if _id in nodes_dict:
                node = nodes_dict[_id]
            elif _id.isdigit():
                _id_int = int(_id)
                if _id_int < next_node_number:
                    node = nodes[_id_int - 1]

            if node is None:
                node = Node(_id, None)
                nodes_dict[_id] = node
                nodes.append(node)
                next_node_number += 1
            node.update_cond(cond_str)

            if n != 0:
                link_str = nodes_splitted[n-1]
                if "1" in link_str:
                    link_cn = "1"
                elif "2" in link_str:
                    link_cn = "2"
                elif "*" in link_str or "?" in link_str:
                    link_cn = "*"
                else:
                    link_cn = None
                edges.append((last_node, link_cn, node))

            last_node = node

    write_dot(dot_file, pattern_name, nodes, edges)


def get_dot_path_from_string(str_in, pattern_name="tmp"):
    tmp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".grapp")
    convert_export_str_to_dot(str_in, tmp_file, pattern_name)
    tmp_file.flush()
    tmp_file.close()

    return tmp_file.name


def main():
    if len(sys.argv) >= 2:
        str_in = sys.argv[1]
        return get_dot_path_from_string(str_in)

if __name__ == "__main__":
    print main()
