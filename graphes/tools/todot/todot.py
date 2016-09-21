#!/usr/bin/env python
import sys
from pygrap import *

def main():
    """
    main
    """
    if len(sys.argv) <= 2:
        print("Usage: ./todot (in.dot) (out.dot)\n")
        exit(-1)

    pathin = sys.argv[1]
    pathout = sys.argv[2]

    gr = getGraphFromFile(pathin)

    if gr is not None:
        graph_fprint(pathout, gr)

if __name__ == '__main__':
    main()
