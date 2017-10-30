#!/usr/bin/env python

from os.path import abspath, dirname
import os

# Project root
ROOT = dirname(abspath(__file__))


# Config
config = {
    "patterns_path": ROOT + os.path.sep + ".." + os.path.sep + "patterns" + os.path.sep,
    "icons_path": ROOT + os.path.sep + ".." + os.path.sep + "ui" + os.path.sep + "icons" + os.path.sep,
    "version": "1.0.0",
    "name": "IDAgrap"
}

# Patterns Definitions
MIN_THRESHOLD = 0.0
MAX_THRESHOLD = 1.0
