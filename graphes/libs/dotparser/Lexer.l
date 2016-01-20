%{
 
/*
 * Lexer.l file
 * To generate the lexical analyzer run: "flex Lexer.l"
 */
 
#include "Expression.h"
#include "Parser.h"

#include <stdio.h>
 
%}

%option outfile="Lexer.c" header-file="Lexer.h"
%option warn nodefault
 
%option reentrant noyywrap never-interactive nounistd
%option bison-bridge
 
DIGRAPH_HEADER  [dD]igraph
IGNORE    "labeljust=r"
IDS       [a-zA-Z0-9*+.]+
IDC       \"[a-zA-Z0-9*+-._: \\(),\[\]]*\"
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
 
{DIGRAPH_HEADER}      { debug_print("digraph header!\n"); return TOKEN_DIGRAPH_HEADER; }
{IDS}         { yylval->type_string = strdup(yytext); debug_print("ids: "); debug_print(yytext); debug_print("\n"); return TOKEN_ID; }
{IDC}         { yylval->type_string = strdup(yytext); debug_print("idc: "); debug_print(yytext); debug_print("\n"); return TOKEN_ID; }
{LENS}        { debug_print("lens!\n"); return TOKEN_LENS; }
{RENS}        { debug_print("rens!\n"); return TOKEN_RENS; }
{LCRO}        { debug_print("lcro!\n"); return TOKEN_LCRO; }
{RCRO}        { debug_print("rcro!\n"); return TOKEN_RCRO; }
{EQ}          { debug_print("eq!\n"); return TOKEN_EQ; }
{VIRG}        { debug_print("virg!\n"); return TOKEN_VIRG; }
{ARROW}       { debug_print("arrow!\n"); return TOKEN_ARROW; }
.             { }
 
%%

void yyerror (char *msg) {
    fprintf(stderr, "Error while parsing dot file. Exiting. Error message: %s.\n", msg);
    exit(1);
    // return 0;
}