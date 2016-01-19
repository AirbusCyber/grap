/*
 * main.c file
 */

#include "main.h"
 

 
int main(void)
{
    graph_t *e = NULL;
    char test[]=" 4 + 2*10 + 3*( 5 + 1 )";
    char test2[]="digraph G {}";
    char test3[]="digraph {}";
    char test4[]="digraph {4}";
    char test5[]="digraph {v5}";
    char test6[]="""digraph {"
		 "\"5\" [v1=ahah]"
		"}";
    char test7[]="""digraph {"
		 "\"6\" [v1=ahah, v2=\"bouh\"]"
		"}";
    char test8[]="""digraph {"
		 "\"6\" [v1=ahah, v2=\"bouh\"]"
		 "\"7\" [v1=bhbh, v3=\"bouh\"]"
		 "\"8\" [v1=bhbh, v3=\"bouh\"]"
		 "\"7\" [v1=bhbh, v3=\"bouh\"]"
		"}";
    char test9[]="""digraph {"
		 "\"6\" [v1=ahah, v2=\"bouh\"]"
		 "\"7\" [v1=bhbh, v3=\"bouh\"]"
		 "\"8\" [v1=bhbh, v3=\"bouh\"]"
		 "\"7\" [v1=bhbh, v3=\"bouh\"]"
		"}";
    char test10[]="""digraph {"
		 "\"6\" [v1=ahah, v2=\"bouh\"]"
		 "\"5\" [v1=ahah, label=\"RET\"]"
		 "\"7\" [label=INST, v3=\"bouh\"]"
		 "\"8\" [label=JCC, v3=\"bouh\"]"
		 "\"7\" [v1=bhbh, v3=\"bouh\"]"
		"}";
    char test11[]="""digraph {"
		 "\"6\" [v1=ahah, v2=\"bouh\"]"
		 "\"5\" [v1=ahah, label=\"RET\"]"
		 "\"7\" [label=INST, v3=\"bouh\"]"
		 "\"8\" [label=JCC, v3=\"bouh\"]"
		 "\"7\" [v1=bhbh, v3=\"bouh\"]"
		 "\"6\" -> \"5\""
		"}";
    char test12[]="""Digraph G {"
		  "\"36\" [label = INST]"
		  "\"35\" [label = UNDEFINED]"
		  "\"37\" [label = INST]"
		  "\"38\" [label = JCC]"
		  "\"36\" -> \"35\" [label = \"0\"]"
		  "}";
    int result = 0;
    printf("in: '%s'\n", test12);
    e = getGraph(test12);
    
    printf("out:\n");
    graph_fprint(stdout, e);
 
    graph_free(e);
 
    return 0;
}