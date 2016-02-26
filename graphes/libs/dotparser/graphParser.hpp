#ifndef GRAPHPARSER_H
#define GRAPHPARSER_H

#include "Expression.hpp"
#include "Parser.hpp"
#include "Lexer.h"

#include "graph.hpp"
#include "graphIO.hpp"
 
#include <stdio.h>

extern "C" { 
graph_t* getGraph(const char *expr);
graph_t* getGraphFromPath(const char* path);
}

graph_t* getGraph(const char *expr);
graph_t* getGraphFromPath(const char* path);
graph_t* getGraphFromFile(FILE* f);

#endif