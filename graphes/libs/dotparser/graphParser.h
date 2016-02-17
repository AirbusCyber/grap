#ifndef GRAPHPARSER_H
#define GRAPHPARSER_H

#include "Expression.h"

extern "C" {
#include "Parser.h"
#include "Lexer.h"
}

#include "graph.h"
#include "graphIO.h"
 
#include <stdio.h>

#ifdef __cplusplus
extern "C" { 
graph_t* getGraph(const char *expr);
graph_t* getGraphFromPath(const char* path);
}
#endif

graph_t* getGraph(const char *expr);
graph_t* getGraphFromPath(const char* path);
graph_t* getGraphFromFile(FILE* f);
int test43(int);

#endif