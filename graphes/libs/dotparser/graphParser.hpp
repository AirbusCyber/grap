#ifndef GRAPHPARSER_H
#define GRAPHPARSER_H

#include "Expression.hpp"
#include "Parser.hpp"
#include "Lexer.hpp"

#include "graph.hpp"
#include "graphIO.hpp"
 
#include <stdio.h>

GraphList* getGraphList(const char *expr);
graph_t *getGraph (const char *expr);
GraphList* getGraphListFromPath(const char* path);
graph_t* getGraphFromPath(const char* path);
GraphList* getGraphListFromFile(FILE* f);
graph_t* getGraphFromFile(FILE* f);
graph_t* popfreeFirstGraph(GraphList* gl);

#endif

