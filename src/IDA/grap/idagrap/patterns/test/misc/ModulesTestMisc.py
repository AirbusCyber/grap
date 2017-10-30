#!/usr/bin/env python

from os import listdir
from os.path import abspath, dirname, sep

from idagrap.modules.Module import ModuleTestMisc
from idagrap.modules.Pattern import Pattern, Patterns


def get_test_misc():
    # Definition----------------------------------------------------------------
    ROOT = dirname(abspath(__file__))
    DIR = sep + "files"
    FULL_PATH = ROOT + DIR
    EXT = ".dot"

    # Tuple of stream ciphers
    TEST_MISC = []

    # For all misc patterns
    for dot in listdir(FULL_PATH):
        if dot.endswith(EXT):
            pattern = Pattern(f=FULL_PATH + sep + dot,
                              name=dot,
                              description=dot + " pattern",
                              min_pattern=1,
                              max_pattern=10)
            patterns = Patterns(patterns=[pattern],
                                threshold=1.0,
                                name=dot + " patterns",
                                description=dot + " patterns",
                                perform_analysis=False)
            module = ModuleTestMisc(
                patterns=[patterns],
                name=dot + " module",
                description=dot + " module"
            )

            TEST_MISC.append(module)
    return TEST_MISC
