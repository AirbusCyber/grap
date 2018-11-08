#!/usr/bin/env python

import os
from os.path import abspath, dirname, sep

from idagrap.modules.Module import ModuleTestMisc
from idagrap.modules.Pattern import Pattern, Patterns
from idagrap.config.General import config


def get_test_misc():
    # Definition----------------------------------------------------------------
    ROOT = dirname(abspath(__file__))
    DIR = sep + "files"
    FULL_PATHS = [ROOT + DIR]
    if "user_patterns_path" in config:
        FULL_PATHS.append(config["user_patterns_path"])
    EXT = [".grapp", ".dot"]

    # Tuple of stream ciphers
    TEST_MISC = []

    # For all misc patterns
    for p in FULL_PATHS:
        rec_listdir = [(os.path.join(dp, f), f) for dp, dn, fn in os.walk(p, followlinks=True) for f in fn]
        for dotpath, dot in rec_listdir:
            ext_ok = False
            for e in EXT:
                if dot.endswith(e):
                    ext_ok = True
                    break
            if ext_ok:
                pattern = Pattern(f=dotpath,
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
