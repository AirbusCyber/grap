#!/usr/bin/env python

from os.path import abspath, dirname

# Project root
ROOT = dirname(abspath(__file__))


# Config
config = {
    "patterns_path": ROOT + "/../patterns/",
    "icons_path": ROOT + "/../ui/icons/",
    "version": "1.0.0",
    "name": "IDAgrap"
}

# Patterns Definitions
MIN_THRESHOLD = 0.0
MAX_THRESHOLD = 1.0
