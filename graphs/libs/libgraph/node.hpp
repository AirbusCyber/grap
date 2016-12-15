#ifndef NODE_H
#define NODE_H

/*!
 @file node.h
 @brief Structures and routines for nodes of a graph.
 */

#include <stdlib.h>
#include <string.h>

#include "ga_types.hpp"
#include "node_info.hpp"

struct node_t;
/*!
 @brief Structure describing a node in a graph.
 */
typedef struct node_t {
  /*!
   @brief Id of the node.

   For statically extraction code address is chosen (begin or maybe end of
   block).
   */
  std::string str_id;
  vsize_t node_id;

  NodeInfo* info;
  
  // Only for patterns
  // TODO: differentiate parsing of pattern and test graphs, fill has_condition
//   bool has_condition;
  CondNode* condition;
  
  /*!
   @brief Number of fathers.
   */
  vsize_t fathers_nb;

  /*!
   Number of children.
   */
  vsize_t children_nb;

  /*!
   @brief Table of pointers to the predecessors of the node.

   To retrieve the i-th father use node_father().
   @see node_father()
   */
  struct node_t** fathers;

  bool has_child1;
  node_t* child1;
  
  bool has_child2;
  node_t* child2;

  // id of the node in the nodelist
  vsize_t list_id;
  
  
} node_t;

/*!
 @brief Allocate a node.
 @return The newly malloc'ed node.
 */
node_t* node_alloc();

/*!
 @brief Overwrite a node with an other.

 Internal structures of node1 are free'd.
 @param node1 Pointer on the node to overwrite.
 @param node2 Pointer on the node to copy.
 @return node1
 */
node_t* node_copy(node_t* node1, const node_t* node2);

/*!
 @brief Free the node.
 @param node The node to free.
 */
void node_free(node_t* node, bool free_info);

/*!
 @brief Add a child to the node children list.
 @param node the node we add a child to.
 @param child the child node.
 @see node_new_child() node_child()
 */
void node_link(node_t* node, node_t* child, bool is_child1);

/*!
 @brief Get the i-th father of a node.
 @param node The node from which to get the father.
 @param index The index of the father to get.
 @return The i-th father of a node if i is valid, otherwise it returns a NULL
 pointer.
 */
node_t* node_father(node_t* node, size_t index);

/*!
 @brief Remove all instances of a node from the fathers node list of a node.
 @param node The node from which remove the father.
 @param to_remove The father to remove.
 */
void node_remove_father(node_t* node, node_t* to_remove);

/*!
 @brief Remove all instances of a node from the children node list of a node.
 @param node The node from which remove the child.
 @param to_remove The child to remove.
 */
void node_remove_child(node_t* node, node_t* to_remove);

#endif
