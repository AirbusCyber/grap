#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys

def ida_get_cfg_raw():
    if "idaapi" not in sys.modules:
        print "ERROR: idaapi not loaded"
        return None
    
    import idaapi
    tw = idaapi.find_tform("IDAgrap")
    if tw is not None:
        import idagrap
        # Get CFG from existing loaded IDAgrap
        w = idaapi.PluginForm.FormToPyQtWidget(tw)
        pgw=w.findChild(idagrap.ui.widgets.PatternGenerationWidget.PatternGenerationWidget)
        cfg = pgw.cc.PatternGenerator.graph
        return cfg
    else:
        # Load grap and creates new CFG object
        fp, pathname, description = imp.find_module("grap")
        _mod = imp.load_module("grap", fp, pathname, description)
        cfg = _mod.CFG()
        return cfg


def ida_get_cfg():
    if "idaapi" in sys.modules:
        # Within IDA
        cfg = ida_get_cfg_raw()
        if not cfg.graph:
            cfg.extract()
        return cfg
    else:
        print "ERROR: idaapi not loaded"
        return None

def ida_match(pattern_str, getids=True, print_matches=True):
    cfg = ida_get_cfg()
    if pattern_str != "" and cfg is not None:
        matches = match_graph(pattern_str, cfg.graph)
        if print_matches:
            print matches_tostring(matches, getids)
        return matches
    else:
        print "ERROR: pattern_str == "" or cfg is None"
        return None


def ida_quick_match(str_in, pattern_name="quick_pattern", getids=True, print_pattern=False, print_matches=True):
    pattern_str = quick_pattern(str_in, pattern_name)
    if print_pattern:
        print "Generated the following pattern:"
        print pattern_str
    return ida_match(pattern_str, getids, print_matches)

