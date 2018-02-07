" Syntax file for grap extensions (.grapp, .grapcfg) adapted from existing dot
" syntax file (see below)

" Vim syntax file
" Language:     Dot
" Filenames:    *.dot
" Maintainer:   Markus Mottl  <markus.mottl@gmail.com>
" URL:          http://www.ocaml.info/vim/syntax/dot.vim
" Last Change:  2011 May 17 - improved identifier matching + two new keywords
"               2001 May 04 - initial version

" For version 5.x: Clear all syntax items
" For version 6.x: Quit when a syntax file was already loaded
if version < 600
  syntax clear
elseif exists("b:current_syntax")
  finish
endif

" Errors
syn match    dotParErr     ")"
syn match    dotBrackErr   "]"
syn match    dotBraceErr   "}"
syn match    dotSingleQuoteErr   "'"
syn match    dotDoubleQuoteErr   "\""

" Enclosing delimiters
syn region   dotEncl transparent matchgroup=dotParEncl start="(" matchgroup=dotParEncl end=")" 
syn region   dotEncl transparent matchgroup=dotBrackEncl start="\[" matchgroup=dotBrackEncl end="\]"
syn region   dotEncl transparent matchgroup=dotBraceEncl start="{" matchgroup=dotBraceEncl end="}"
syn region   dotEncl transparent matchgroup=dotSingleQuoteEncl start="'" matchgroup=dotSingleQuoteEncl end="'"
syn region   dotEncl transparent matchgroup=dotDoubleQuoteEncl start="\"" matchgroup=dotDoubleQuoteEncl end="\""

" grap
syn region   condArg transparent matchgroup=dotType start="cond\(ition\)\= *= *" end="[,\]]" skip="'.*'" contains=condKeywords, condBoolOperators, condStringOperators, condNumberOperators, condArgArg, condProperty
syn region   condArg transparent matchgroup=dotType start="cond\(ition\)\= *= *\"" end="\"" skip="'.*'" contains=condKeywords, condBoolOperators, condStringOperators, condNumberOperators, condArgArg, condProperty
syn region   condArgArg start="'" end="'"

" Comments
syn region   dotComment start="//" end="$" contains=dotComment,dotTodo
syn region   dotComment start="/\*" end="\*/" contains=dotComment,dotTodo
syn keyword  dotTodo contained TODO FIXME XXX

" Strings
"syn region   dotString    start=+"+ skip=+\\\\\|\\"+ end=+"+

" General keywords
syn keyword  dotKeyword  digraph node edge subgraph


" Graph attributes
syn keyword  dotType center layers margin mclimit name nodesep nslimit
syn keyword  dotType ordering page pagedir rank rankdir ranksep ratio
syn keyword  dotType rotate size

" Node attributes
syn keyword  dotType distortion fillcolor fontcolor fontname fontsize
syn keyword  dotType height layer orientation peripheries regular
syn keyword  dotType shape shapefile sides skew width
" grap
"syn keyword  dotType cond condition
syn keyword  dotType addr address inst instruction
syn keyword  dotType root repeat minrepeat maxrepeat lazyrepeat
syn keyword  dotType minfathers maxfathers minchildren maxchildren
syn keyword  dotType getid

" Edge attributes
syn keyword  dotType arrowhead arrowsize arrowtail constraint decorateP
syn keyword  dotType dir headclip headlabel headport labelangle labeldistance
syn keyword  dotType labelfontcolor labelfontname labelfontsize
syn keyword  dotType minlen port_label_distance samehead sametail
syn keyword  dotType tailclip taillabel tailport weight
" grap
syn keyword  dotType childnumber child_number


syn keyword  condKeywords instruction inst opcode address addr contained
syn keyword  condKeywords nargs arg1 arg2 arg3 nfathers nchildren contained
syn keyword  condStringOperators is beginswith regex bacblockend contained
syn keyword  condProperty basicblockend contained
syn match  condStringOperators "contains" contained
syn match  condNumberOperators ">" contained
syn match  condNumberOperators ">=" contained
syn match  condNumberOperators "<" contained
syn match  condNumberOperators "<=" contained
syn keyword  condBoolOperators true not and or contained

" Shared attributes (graphs, nodes, edges)
syn keyword  dotType color

" Shared attributes (graphs and edges)
syn keyword  dotType bgcolor label URL

" Shared attributes (nodes and edges)
syn keyword  dotType fontcolor fontname fontsize layer style

" Special chars
"syn match    dotKeyChar  "="
syn match    dotKeyChar  ";"
syn match    dotKeyChar  "->"

" Identifier
"syn match    dotIdentifier /\<\w\+\(:\w\+\)\?\>/

" Synchronization
syn sync minlines=50
syn sync maxlines=500

" Define the default highlighting.
" For version 5.7 and earlier: only when not done already
" For version 5.8 and later: only when an item doesn't have highlighting yet
if version >= 508 || !exists("did_dot_syntax_inits")
  if version < 508
    let did_dot_syntax_inits = 1
    command -nargs=+ HiLink hi link <args>
  else
    command -nargs=+ HiLink hi def link <args>
  endif

  HiLink dotParErr	 Error
  HiLink dotBraceErr	 Error
  HiLink dotBrackErr	 Error
  HiLink dotSingleQuoteErr	 Error
  HiLink dotDoubleQuoteErr	 Error

  HiLink dotComment	 Comment
  HiLink condArgArg	 Default
  HiLink dotTodo	 Todo

  HiLink dotParEncl	 Keyword
  HiLink dotBrackEncl	 Keyword
  HiLink dotBraceEncl	 Keyword
  HiLink dotSingleQuoteEncl	 Keyword
  HiLink dotDoubleQuoteEncl	 Keyword

  HiLink dotKeyword	 Keyword
  HiLink dotType	 Type
  HiLink dotKeyChar	 Keyword

  HiLink dotString	 String
  HiLink dotIdentifier	 Identifier

  HiLink condRegion	 Comment
  HiLink condEncl	 Comment
  HiLink condKeywords	 Special
  HiLink condNumberOperators	 Special
  HiLink condStringOperators	 Special
  HiLink condProperty	 Special
  HiLink condBoolOperators	 Constant

  delcommand HiLink
endif

let b:current_syntax = "grapp"
let b:current_syntax = "grapcfg"

" vim: ts=8
