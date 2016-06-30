#!/usr/bin/env python

from os.path import abspath, dirname

from idagrap.modules.Pattern import Pattern, Patterns

ROOT = dirname(abspath(__file__))

RC4_SET_KEY = Patterns(
    patterns=[
        Pattern(ROOT + "/loop1.dot"),  # RC4 set key first loop
        Pattern(ROOT + "/loop2.dot"),  # RC4 set key second loop
    ],
    threshold=1.0
)
