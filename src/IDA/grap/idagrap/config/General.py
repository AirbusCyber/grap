#!/usr/bin/env python

from os.path import abspath, dirname
import os

# Project root
ROOT = dirname(abspath(__file__))


# Config
config = {
    "patterns_path": ROOT + os.path.sep + ".." + os.path.sep + "patterns" + os.path.sep,
    "icons_path": ROOT + os.path.sep + ".." + os.path.sep + "ui" + os.path.sep + "icons" + os.path.sep,
    "about_path": ROOT + os.path.sep + ".." + os.path.sep + "ui" + os.path.sep + "widgets" + os.path.sep + "about.html",
    "version": "1.0.0",
    "name": "IDAgrap"
}

try:
    if os.name == "nt":
        appdata_path = os.getenv("APPDATA")
        user_grap_path = appdata_path + os.path.sep + "IDAgrap"
        if not os.path.exists(user_grap_path):
            os.makedirs(user_grap_path)
        config["user_patterns_path"] = user_grap_path + os.path.sep + "patterns"
        if not os.path.exists(config["user_patterns_path"]):
            os.makedirs(config["user_patterns_path"])
except Exception as e:
    print "WARNING:", e

# Patterns Definitions
MIN_THRESHOLD = 0.0
MAX_THRESHOLD = 1.0
