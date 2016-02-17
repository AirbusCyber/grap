

/*
 * Expression.h
 * Definition of the structure used to build the syntax tree.
 */
#ifndef __EXPRESSION_H__
#define __EXPRESSION_H__

#include "graph.h"
#include "graphIO.h"
// #include <cstddef>
#include <stddef.h>
#include <string.h>

// graph_t* graph_alloc(vsize_t max_size);
// void graph_free(graph_t* graph);

typedef struct Couple
{
  uint x;
  uint y;
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

#ifdef __cplusplus
extern "C" { 
void debug_print(char*);
CoupleList* createEdgeList();
CoupleList* addEdgeToList(Couple* c, CoupleList* cl);
Couple* createEdge(char* f, char* c, OptionList* ol);
graph_t* addEdgesToGraph(CoupleList* cl, graph_t* g);
node_t* updateNode(OptionList* ol, node_t* n);
OptionList* createOptionList();
OptionList* addOptionToList(Option* o, OptionList* ol);
Option* createOption(char* I, char* V);
node_t *createNode(char* value);
graph_t *createGraph();
graph_t* addNodeToGraph(node_t* n, graph_t* g);
}
#endif


uint hash(char* s);

void debug_print(char* s);

CoupleList* createEdgeList();

CoupleList* addEdgeToList(Couple* c, CoupleList* cl);

Couple* createEdge(char* f, char* c, OptionList* ol);

graph_t* addEdgesToGraph(CoupleList* cl, graph_t* g);

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