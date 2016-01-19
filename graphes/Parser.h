/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_YY_PARSER_H_INCLUDED
# define YY_YY_PARSER_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int yydebug;
#endif
/* "%code requires" blocks.  */
#line 19 "libs/dotparser/Parser.y" /* yacc.c:1909  */


#ifndef YY_TYPEDEF_YY_SCANNER_T
#define YY_TYPEDEF_YY_SCANNER_T
typedef void* yyscan_t;
#endif


#line 53 "Parser.h" /* yacc.c:1909  */

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    TOKEN_DIGRAPH_HEADER = 258,
    TOKEN_ID = 259,
    OPTION_ID = 260,
    TOKEN_OPTION_STR = 261,
    TOKEN_LENS = 262,
    TOKEN_RENS = 263,
    TOKEN_LCRO = 264,
    TOKEN_RCRO = 265,
    TOKEN_EQ = 266,
    TOKEN_VIRG = 267,
    TOKEN_ARROW = 268,
    TOKEN_NUMBER = 269
  };
#endif
/* Tokens.  */
#define TOKEN_DIGRAPH_HEADER 258
#define TOKEN_ID 259
#define OPTION_ID 260
#define TOKEN_OPTION_STR 261
#define TOKEN_LENS 262
#define TOKEN_RENS 263
#define TOKEN_LCRO 264
#define TOKEN_RCRO 265
#define TOKEN_EQ 266
#define TOKEN_VIRG 267
#define TOKEN_ARROW 268
#define TOKEN_NUMBER 269

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 38 "libs/dotparser/Parser.y" /* yacc.c:1909  */

    char* type_string;
    int value;
    graph_t* Sgraph;
    node_t* Snode;
    Option* Soption;
    OptionList* SoptionList;
    Couple* Sedge;
    CoupleList* SedgeList;

#line 104 "Parser.h" /* yacc.c:1909  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif



int yyparse (graph_t **Sgraph, yyscan_t scanner);

#endif /* !YY_YY_PARSER_H_INCLUDED  */
