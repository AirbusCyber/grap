%{
 
/*
 * Lexer.l file
 * To generate the lexical analyzer run: "flex Lexer.l"
 */

#include "Expression.hpp"
#include "Parser.hpp"

#include <stdio.h>
 
/* IDS: simple labels (aaa, 7ffs)
 * IDC: labels with quotes ("hello", "z97(e,e)", "xor eax, eax")
 * IDV: labels with comparisons ("inst >= xor", "opcode==add", "inst == xor eax, eax")
 */
 
%}

%option warn nodefault
 
%option reentrant noyywrap never-interactive nounistd
%option bison-bridge
 
DIGRAPH_HEADER  [dD]igraph
COMMENT_LINE  ^" "*"//".*
IGNORE    "labeljust=r"
IDS       [a-zA-Z0-9*+._]+
IDC       \"[a-zA-Z0-9*+-._: \\(),\[\]]*\"
IDV       \"[a-zA-Z0-9*+-._: \\(),\[\]=!<>^$?|{}']*\"
LENS      "{"
RENS      "}"
LCRO      "["
RCRO      "]"
EQ        "="
VIRG      ","
ARROW     "->"
 
WS        [ \r\n\t]*
 
%%
 
{IGNORE}      { }
{WS}          { }
{COMMENT_LINE}  { }
 
{DIGRAPH_HEADER}      { debug_print((char *) "digraph header!\n"); return TOKEN_DIGRAPH_HEADER; }
{IDS}         { yylval->type_string = strdup(yytext); debug_print((char *) "ids: "); debug_print(yytext); debug_print((char *) "\n"); return TOKEN_ID; }
{IDC}         { yylval->type_string = strdup(yytext); debug_print((char *) "idc: "); debug_print(yytext); debug_print((char *) "\n"); return TOKEN_ID; }
{IDV}         { yylval->type_string = strdup(yytext); debug_print((char *) "idc: "); debug_print(yytext); debug_print((char *) "\n"); return TOKEN_IDV; }
{LENS}        { debug_print((char *) "lens!\n"); return TOKEN_LENS; }
{RENS}        { debug_print((char *) "rens!\n"); return TOKEN_RENS; }
{LCRO}        { debug_print((char *) "lcro!\n"); return TOKEN_LCRO; }
{RCRO}        { debug_print((char *) "rcro!\n"); return TOKEN_RCRO; }
{EQ}          { debug_print((char *) "eq!\n"); return TOKEN_EQ; }
{VIRG}        { debug_print((char *) "virg!\n"); return TOKEN_VIRG; }
{ARROW}       { debug_print((char *) "arrow!\n"); return TOKEN_ARROW; }
.             { }
 
%%

void yyerror (char *msg) {
    fprintf(stderr, "Error while parsing dot file. Exiting. Error message: %s.\n", msg);
    RELEASE_ASSERT(false);
}
