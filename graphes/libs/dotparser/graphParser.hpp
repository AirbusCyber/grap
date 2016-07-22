#ifndef GRAPHPARSER_H
#define GRAPHPARSER_H

#include "Expression.hpp"
#include "Parser.hpp"
#include "Lexer.hpp"

#include "graph.hpp"
#include "graphIO.hpp"
 
#include <stdio.h>

graph_t* getGraph(const char *expr);
graph_t* getGraphFromPath(const char* path);
graph_t* getGraphFromFile(FILE* f);

#endif

