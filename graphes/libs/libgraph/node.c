#include "node.h"

node_t *node_alloc () {
  node_t *node = MY_ZALLOC (1, node_t);

  /*
     use zalloc() !
     node->symb = SYMB_INIT;
     node->code_add = 0;
     node->code_length = 0;
     node->explored = UNEXPLORED;
     node->children_nb = 0;
     node->fathers_nb = 0;
     node->children = NULL;
     node->fathers = NULL;
   */

  return node;
}

void node_set_children_nb (node_t * node, vsize_t nb) {
  node->children_nb = nb;
  node->children = MY_REALLOC (node->children, node->children_nb, node_t *);
}

void node_set_fathers_nb (node_t * node, vsize_t nb) {
  node->fathers_nb = nb;
  node->fathers = MY_REALLOC (node->fathers, node->fathers_nb, node_t *);
}

void node_reset (node_t * node) {
  MY_FREE (node->fathers);
  MY_FREE (node->children);

  MY_BZERO (node);
  /* USE bzero()
     node->explored = UNEXPLORED;

     node->fathers_nb = 0;
     node->children_nb = 0;

     node->fathers = NULL;
     node->children = NULL;
   */
}

node_t *node_copy (node_t * node1, const node_t * node2) {
  /* free tables of fathers/children */
  MY_FREE (node1->fathers);
  MY_FREE (node1->children);

  memcpy (node1, node2, sizeof (node_t));

  /* copy fathers */
  if (node2->fathers_nb > 0) {
    node1->fathers = MY_MALLOC (node2->fathers_nb, node_t *);
    memcpy (node1->fathers, node2->fathers, node1->fathers_nb * sizeof (node_t *));
  }

  /* copy children */
  if (node2->fathers_nb > 0) {
    node1->children = MY_MALLOC (node2->children_nb, node_t *);
    memcpy (node1->children, node2->children, node2->children_nb * sizeof (node_t *));
  }
  return node1;
}

void node_free (node_t * node) {
  MY_FREE (node->children);
  MY_FREE (node->fathers);
  MY_FREE (node);
}

void node_link (node_t * node, node_t * child) {
  node_set_children_nb (node, node->children_nb + 1);
  node->children[node->children_nb - 1] = child;
  node_set_fathers_nb (child, child->fathers_nb + 1);
  child->fathers[child->fathers_nb - 1] = node;
}

node_t *node_child (node_t * node, size_t index) {
  if (index >= node->children_nb)
    return NULL;
  return node->children[index];
}

const node_t *node_child_const (const node_t * node, size_t index) {
  if (index >= node->children_nb)
    return NULL;
  return node->children[index];
}

node_t *node_father (node_t * node, size_t index) {
  if (index >= node->fathers_nb)
    return NULL;
  return node->fathers[index];
}

const node_t *node_father_const (const node_t * node, size_t index) {
  if (index >= node->fathers_nb)
    return NULL;
  return node->fathers[index];
}

void node_init_unexplored (node_t * node) {
  node->explored = UNEXPLORED;
}

void node_remove_father (node_t * node, node_t * to_remove) {
  vsize_t i, shift;

  shift = 0;
  for (i = 0; i < node->fathers_nb; ++i) {
    node_t *current = node_father (node, i);
    if (current == to_remove)
      ++shift;
    else
      node->fathers[i - shift] = current;
  }
  node_set_fathers_nb (node, i - shift);
}

void node_remove_child (node_t * node, node_t * to_remove) {
  vsize_t i, shift;

  shift = 0;
  for (i = 0; i < node->children_nb; ++i) {
    node_t *current = node_child (node, i);
    if (current == to_remove)
      ++shift;
    else
      node->children[i - shift] = current;
  }
  node_set_children_nb (node, i - shift);
}
