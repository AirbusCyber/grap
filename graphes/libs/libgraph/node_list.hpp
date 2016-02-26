#ifndef NODE_LIST_H
#define NODE_LIST_H

#include "node.hpp"
#include "dict.hpp"
  
/*!
 @file node_list.h
 @brief Wrapper preventing from using dv_t for node list.

 Now node pointers list has it own type, different from dv_t.
 Help to make a clear distinction between arrays of node_t (in graph_t) and
 arrays of node_t*.

 @see node_ptr_list.h
 */
struct _dv_t;
struct node_list_iterator_t;

/*!
 @brief The node list structure.
 */
typedef struct node_list_t {
  /*!
   @brief Array for storing nodes.

   We can't use dv_t because node stores pointers to children and father, and
   a realloc would break them. If we really want to use dv_t, we must never add
   or remove any node after creating edges. This is too dangerous, so we use a
   static array.
   */
  node_t **storage;

  /*!
   @brief Size of the node array.
   */
  vsize_t size;

  /*!
   @brief Number of node allocated in the node array.
   */
  vsize_t count;
  
  /*!
  @brief Dictionary (or map) used when loading graph from dot file
  */
  struct dict *nodes_dict;
} node_list_t;

/*!
 @brief Initialize the list.
 @param list The list to initialize.
 */
void node_list_build(node_list_t * list, vsize_t max_size);

void node_list_add(node_list_t * list, node_t* node);

/*!
 @brief Free all internal structures used.
 @param list The list to free.
 */
void node_list_free(node_list_t * list);

/*!
 @brief Reset the list.
 @param list The list to reset.
 */
// void node_list_reset(node_list_t * list);

/*!
 @brief Get the i-th node of the node_list.
 @param list The node list.
 @param index The index i.
 */
node_t * node_list_item(const node_list_t * list, vsize_t index);

/*!
 @brief Set all nodes as unexplored
 @param list The node list.
 */
void node_list_set_all_unexplored(node_list_t * list);

/*!
 @brief Get the number of nodes in the list.
 @param list The node list.
 @return Number of nodes.
 */
vsize_t node_list_size(const node_list_t * list);

/*!
 @brief Add an empty node to the list at index node_id.
 Node index must not already exist !
 @param list The node list.
 @param node_id The unique index of the new node.
 @return Created node in the list.
 */
node_t* node_list_append(node_list_t * list, uint64_t node_id);

/*!
 @brief Find the node with node_id inside node list
 Node index must not already exist !
 @param list The node list.
 @param node_id The unique id of the searched node.
 @return Pointer to found node or NULL
 */
node_t* node_list_find(node_list_t * list, uint64_t node_id);

/*!
 @brief Malloc and initialize a new iterator. Next node will be the first.
 @param list The node list.
 @return The new iterator set up to the first node.
 */
struct node_list_iterator_t* node_list_it_new(const node_list_t * list);

/*!
 @brief Free an iterator.
 @param it The iterator to free.
 */
void node_list_it_free(struct node_list_iterator_t* it);

/*!
 @brief Rewind iterator. Next node will be the first.
 @param it Iterator to set up to the first node.
 */
void node_list_it_rewind(struct node_list_iterator_t *it);

/*!
 @brief Move the iterator to the next node, and return a pointer to it.
 @param it Iterator to set up to the first node.
 @return A pointer to the next node, or NULL it reaches the end of list.
 */
node_t * node_list_it_get_next(struct node_list_iterator_t *it);

/*!
 @brief Move the iterator to the previous node, and return a pointer to it.
 @param it Iterator to set up to the first node.
 @return A pointer to the next node, or NULL it reaches the begining of list.
 */
node_t * node_list_it_get_prev(struct node_list_iterator_t *it);

#endif
