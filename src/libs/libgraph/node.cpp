#include "node.hpp"

node_t *node_alloc () {
  node_t *node = (node_t*) calloc_or_quit (1, sizeof(node_t));

  return node;
}

node_t *node_copy (node_t * node1, const node_t * node2) {
  /* free tables of fathers/children */
  free(node1->fathers);

  memcpy (node1, node2, sizeof (node_t));

  /* copy fathers */
  if (node2->fathers_nb > 0) {
    node1->fathers = (node_t**) malloc_or_quit(node2->fathers_nb * sizeof(node_t*));
    memcpy (node1->fathers, node2->fathers, node1->fathers_nb * sizeof (node_t *));
  }

  /* copy children */
  if (node1->children_nb > 0) {
    node1->has_child1 = node2->has_child1;
    node1->child1 = node2->child1;
    node1->has_child2 = node2->has_child2;
    node1->child2 = node2->child2;
  }
  return node1;
}

void node_free (node_t * node, bool free_info) {
  free(node->fathers);
  
  if (free_info){
    // be careful, node info and node conditions are also used in Parcours and ParcoursNode
    delete(node->info);
    node->info = NULL;
    if (node->condition != NULL){
      CondNode::freeCondition(node->condition, true, true);
    }
  }
  
  free(node);
}

void node_link (node_t * node, node_t * child, bool is_wildcard, bool is_child1) {
  if (is_child1){
    if (not node->has_child1) {
      node->children_nb++;
      node->has_child1 = true;
    }
    else{
      std::cerr << "WARNING: Overwriting existing node child." << std::endl; 
    }
    node->child1 = child;
  }
  else {
    if (not node->has_child2) {
      node->children_nb++;
      node->has_child2 = true;
    }
    else{
      std::cerr << "WARNING: Overwriting existing node child." << std::endl; 
    }
    node->child2 = child;
  }
 
  if (is_wildcard){
    node->children_are_wildcards = true; 
  }
 
  child->fathers_nb++;
  child->fathers = (node_t**) realloc_or_quit(child->fathers, child->fathers_nb * sizeof(node_t*));
  child->fathers[child->fathers_nb - 1] = node;
}

node_t *node_father (node_t * node, size_t index) {
  if (index >= node->fathers_nb)
    return NULL;
  return node->fathers[index];
}

void node_remove_father (node_t * node, node_t * to_remove) {
  vsize_t i, shift;

  shift = 0;
  for (i = 0; i < node->fathers_nb; ++i) {
    node_t *current = node_father (node, i);
    if (current == to_remove){
      ++shift;
    }
    else{
      node->fathers[i - shift] = current;  
    }
  }
  node->fathers_nb =  i - shift;
  node->fathers = (node_t**) realloc_or_quit(node->fathers, node->fathers_nb * sizeof(node_t*));
}

void node_remove_child (node_t * node, node_t * to_remove) { 
  if (node->has_child1){
    if (node->child1 == to_remove){
      node->has_child1 = false;
      node->children_nb--;
    }
  }
  
  if (node->has_child2){
    if (node->child1 == to_remove){
      node->has_child2 = false;
      node->children_nb--;
    }
  }
}
