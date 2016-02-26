#ifndef GRAPH_H
#define GRAPH_H

/*!
 @file graph.h
 @brief Structure and methods for rooted and directed graphs support.
 A graph is seen as a list of node with a root.
 */

#include "node.h"
#include "node_list.h"

/*!
 @brief Define a structure for rooted and directed graphs
 */
typedef struct graph_t {
  /*!
   @brief Nodes of the graph.
   @see node_list.h
   */
  node_list_t nodes;

  /*!
   @brief Root of the graph.
   @see node.h
   */
  node_t* root;
} graph_t;

/*!
 @brief Graph construction procedure.
 @return A pointer to the newly allocated graph.
 */
graph_t* graph_alloc(vsize_t max_size);

extern "C" { 
void graph_free(graph_t* graph);
}

/*!
 @brief Graph freeing procedure.
 @param graph The graph to free.
 */
void graph_free(graph_t* graph);

#endif
