#!/usr/bin/env python2
# -*- coding: utf-8 -*-

import sys
import imp

cfg = None
is_cfg_from_idagrap = False

def ida_get_cfg_raw(existing_cfg=None):
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
        return cfg, True
    else:
        # If necessary, load grap and creates new CFG object
        if existing_cfg is None:
            fp, pathname, description = imp.find_module("grap")
            _mod = imp.load_module("grap", fp, pathname, description)
            cfg = _mod.CFG()
            return cfg, False
        return existing_cfg, False


def ida_get_cfg():
    global cfg, is_cfg_from_idagrap

    if "idaapi" in sys.modules:
        # Within IDA
        if cfg is None or not is_cfg_from_idagrap:
            cfg, is_cfg_from_idagrap = ida_get_cfg_raw(cfg)
        if not cfg.graph:
            cfg.extract()
        return cfg
    else:
        print "ERROR: idaapi not loaded"
        return None

def ida_match(pattern_arg, getids=True, print_matches=True):
    cfg = ida_get_cfg()
    if (type(pattern_arg) is list or (type(pattern_arg) is str and pattern_arg != "")) and cfg is not None:
        matches = match_graph(pattern_arg, cfg.graph)
        if print_matches:
            print matches_tostring(matches, getids)
        return matches
    else:
        print "ERROR: pattern_arg is empty string or not a list, or cfg is None"
        return None


def ida_quick_match(str_in, pattern_name="quick_pattern", getids=True, print_pattern=False, print_matches=True):
    pattern_str = quick_pattern(str_in, pattern_name)
    if print_pattern:
        print "Generated the following pattern:"
        print pattern_str
    return ida_match(pattern_str, getids, print_matches)

