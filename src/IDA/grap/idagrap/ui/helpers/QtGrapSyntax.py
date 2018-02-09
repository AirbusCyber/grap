# Adapted from syntax.py found here: https://wiki.python.org/moin/PyQt/Python%20syntax%20highlighting
# Licensed under a modified BSD license http://directory.fsf.org/wiki/License:BSD_3Clause :

# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are
# met:

    # (1) Redistributions of source code must retain the above copyright
    # notice, this list of conditions and the following disclaimer. 

    # (2) Redistributions in binary form must reproduce the above copyright
    # notice, this list of conditions and the following disclaimer in
    # the documentation and/or other materials provided with the
    # distribution.  
    
    # (3)The name of the author may not be used to
    # endorse or promote products derived from this software without
    # specific prior written permission.

# THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
# IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
# SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
# STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING
# IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.

import sys

from PyQt5.QtCore import QRegularExpression
from PyQt5.QtGui import QColor, QTextCharFormat, QFont, QSyntaxHighlighter

def format(color, style=''):
    """Return a QTextCharFormat with the given attributes.
    """
    _color = QColor()
    _color.setNamedColor(color)

    _format = QTextCharFormat()
    _format.setForeground(_color)
    if 'bold' in style:
        _format.setFontWeight(QFont.Bold)
    if 'italic' in style:
        _format.setFontItalic(True)

    return _format


class PythonHighlighter (QSyntaxHighlighter):
    """Syntax highlighter for the Python language.
    """
    
    # Syntax styles
    STYLES = {
        'default': format('black'),
        'dot_keywords': format('green'),
        'comment': format('blue'),
        'cond_keywords': format('purple'),
        'cond_operators': format('purple'),
        'cond_bool_operators': format('red'),
    }
    
    dot_keywords = [
        'digraph', 'node', 'edge', 'fillcolor', 'height',
        'label', 'shape',
        'addr', 'address', 'inst', 'instruction', 'root', 'repeat', 'minrepeat',
        'maxrepeat', 'lazyrepeat', 'minfathers', 'maxfathers', 'minchildren', 'maxchildren',
        'getid', 'childnumber', 'child_number'
    ]
    
    cond_keywords = [
        'instruction', 'inst', 'opcode', 'address', 'addr',
        'nargs', 'arg1', 'arg2', 'arg3', 'nfathers', 'nchildren',
    ]
    
    cond_bool_operators = [
        # Boolean operators
        'true', 'not', 'and', 'or',
    ]
    
    cond_operators = [
        # Number operators
        '==', '!=', '<', '<=', '>', '>=',
        # String operators
        'is', 'beginswith', 'regex', 'contains', 'basicblockend',
    ]
    
    def __init__(self, document):
        QSyntaxHighlighter.__init__(self, document)

        rules = []

        # Keyword, operator, and brace rules
        rules += [(r'\b%s\b' % w, 0, self.STYLES['dot_keywords'], "dot_keywords", [])
            for w in PythonHighlighter.dot_keywords]

        patterns_cond_bool_operators = [(r'\b%s\b' % c, 0, self.STYLES['cond_bool_operators'], "cond_bool_operators", []) for c in PythonHighlighter.cond_bool_operators]    
        rules_cond_bool_operators = [(QRegularExpression(pat), index, fmt, ruleid, subrules) for (pat, index, fmt, ruleid, subrules) in patterns_cond_bool_operators]
        
        patterns_cond_operators = [(r'\b%s\b' % c, 0, self.STYLES['cond_operators'], "cond_operators", []) for c in PythonHighlighter.cond_operators]    
        rules_cond_operators = [(QRegularExpression(pat), index, fmt, ruleid, subrules) for (pat, index, fmt, ruleid, subrules) in patterns_cond_operators]
        
        patterns_cond_keywords = [(r'\b%s\b' % c, 0, self.STYLES['cond_keywords'], "cond_keywords", []) for c in PythonHighlighter.cond_keywords]    
        rules_cond_keywords = [(QRegularExpression(pat), index, fmt, ruleid, subrules) for (pat, index, fmt, ruleid, subrules) in patterns_cond_keywords]
        
        # All other rules
        rules += [
            # Conditions
            (r'cond(ition)? *= *"[^"]*(\\.[^"\\]*)*"', 0, self.STYLES['default'], "cond1", rules_cond_operators+rules_cond_keywords+rules_cond_bool_operators),
            (r'cond(ition)? *=[^,\]]*[,\]]', 0, self.STYLES['default'], "cond2", rules_cond_operators+rules_cond_keywords+rules_cond_bool_operators),

            # Single-quoted string, possibly containing escape sequences
            (r"'[^'\\]*(\\.[^'\\]*)*'", 0, self.STYLES['default'], "singlequotedstrings", []),
            
            # From '//' until a newline: comments
            (r'^//[^\n]*', 0, self.STYLES['comment'], "comment", []),
        ]
        

        # Build a QRegularExpression for each pattern
        self.rules = [(QRegularExpression(pat), index, fmt, ruleid, subrules)
            for (pat, index, fmt, ruleid, subrules) in rules]

    def highlightBlock(self, text):
        """Apply syntax highlighting to the given block of text.
        """
        self._highlightBlock(text, 0, self.rules)

    def _highlightBlock(self, text, relative_pos, rules, maxdepth=1):
        """Recursively apply regex rules
        """
        
        if len(rules) == 0 or maxdepth < 0:
            return
        
        for expression, nth, format, ruleid, subrules in rules:        
            matches = expression.globalMatch(text)

            
            while matches.hasNext():
                match = matches.next() # QRegularExpressionMatch
                beg = match.capturedStart()
                end = match.capturedEnd()
                length = end-beg

                self.setFormat(relative_pos+beg, length, format)
                
                # Dirty trick to color 'cond=' but not the rest of the matched pattern
                if ruleid == "cond1" or ruleid == "cond2":
                    cond_str = text[relative_pos+beg:relative_pos+end].split("=")[0]
                    cond_len = len(cond_str)
                    self.setFormat(relative_pos+beg, cond_len, self.STYLES['dot_keywords'])
                
                if len(subrules) >= 1:
                    self._highlightBlock(text[relative_pos+beg:relative_pos+end], relative_pos+beg, subrules, maxdepth-1)
