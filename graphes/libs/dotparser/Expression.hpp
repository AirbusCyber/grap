/*
 * Expression.h
 * Definition of the structure used to build the syntax tree.
 */
#ifndef __EXPRESSION_H__
#define __EXPRESSION_H__

#include "graph.hpp"
#include "graphIO.hpp"
#include "node_info.hpp"
#include <stddef.h>
#include <string.h>

#include <stdlib.h>
#include <stdio.h>
#include <iostream>


typedef struct GraphList
{
  vsize_t size;
  graph_t** graphes;
} GraphList;

typedef struct Couple
{
  vsize_t x;
  vsize_t y;
  bool is_numbered;
  bool is_child1;
} Couple;

typedef struct CoupleList
{
  vsize_t size;
  Couple** couples;
} CoupleList;

typedef struct Option
{
  char* id;
  char* value;
} Option;

typedef struct OptionList
{
  vsize_t size;
  Option** options;
} OptionList;

vsize_t hash_func(char* s);

void debug_print(char* s);

GraphList* createGraphList();
GraphList* addGraphToInput(graph_t* g, GraphList* gl);
void freeGraphList(GraphList* gl, bool freeGraphs, bool free_info);
typedef std::list<graph_t*> GraphCppList;
GraphCppList MakeGraphList(GraphList* gl);

CoupleList* createEdgeList();
void freeEdgeList(CoupleList* cl);
char *removeQuotes(char *s);

CoupleList* addEdgeToList(Couple* c, CoupleList* cl);

Couple* createEdge(char* f, char* c, OptionList* ol);

graph_t* addEdgesToGraph(char* name, CoupleList* cl, graph_t* g);

node_t* updateNode(OptionList* ol, node_t* n);

OptionList* createOptionList();

OptionList* addOptionToList(Option* o, OptionList* ol);

Option* createOption(char* I, char* V);

/**
 * @brief It creates a node
 * @param value The name of the node
 * @return The graph or NULL in case of no memory
 */
node_t *createNode(char* value);

graph_t *createGraph();

graph_t* addNodeToGraph(node_t* n, graph_t* g);

void freeOption(Option* o);
void freeOptionList(OptionList* ol);

#endif
