#ifndef GRAPH_H
#define GRAPH_H

/*!
 @file graph.h
 @brief Structure and methods for rooted and directed graphs support.
 A graph is seen as a list of node with a root.
 */

#include "node.hpp"
#include "node_list.hpp"

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
  
  std::string name;
  
  bool has_wildcards;
} graph_t;

/*!
 @brief Graph construction procedure.
 @return A pointer to the newly allocated graph.
 */
graph_t* graph_alloc(vsize_t max_size);

/*!
 @brief Graph freeing procedure.
 @param graph The graph to free.
 @param free_info Wether to free nodes' info, be sure that they are not used elsewhere (Parcours).
 */
void graph_free(graph_t* graph, bool free_info);

/*!
 @brief Updates children and fathers numbers in nodes' nodeinfo struct from the node fields
 @param graph The graph to update.
 */
void update_children_fathers_number(graph_t* graph);

#endif
