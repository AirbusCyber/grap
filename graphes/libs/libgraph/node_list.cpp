#include "node_list.hpp"


void node_list_build(node_list_t * list, vsize_t max_size) {
  list->size = max_size;
  list->count = 0;
  list->storage = NULL;
  list->nodes_dict = dict_alloc();
}

void node_list_add(node_list_t * list, node_t* node) {
  node_t* r = dict_find(list->nodes_dict, node->node_id);
  
  if (r == NULL){
    // new node
    list->size++;
    list->storage = (node_t**) realloc(list->storage , list->size * sizeof(node_t*));

    list->storage[list->size-1] = node;
    list->storage[list->size-1]->list_id = list->count;
    list->count++;

    node_t* rr = dict_insert(list->nodes_dict, node->node_id, node);
  }
  else {
    // node already exists 
    printf("Warning: node %x already exists in graph (it was NOT duplicated).\n", (int) node->node_id);
  }
}

void node_list_free(node_list_t * list) {
  vsize_t i;

  for (i = 0; i < list->size; i++) {
    node_free(list->storage[i]);
  }
  
  free(list->storage);
  dict_free(list->nodes_dict);
}

node_t * node_list_item(const node_list_t * list, vsize_t index) {
  return list->storage[index];
}

void node_list_set_all_unexplored(node_list_t * list) {
  vsize_t i;
  for (i = 0; i < list->count; i++) {
    list->storage[i]->explored = UNEXPLORED;
  }
}

vsize_t node_list_size(const node_list_t * list) {
  return list->count;
}

node_t* node_list_append(node_list_t * list, uint64_t node_id) {
  node_t *new_node;

  MY_ASSERT_MSG(list->count < list->size, "Too small node_list");

  new_node = list->storage[list->count];
  new_node->node_id = node_id;
  new_node->list_id = list->count;
  list->count++;

  dict_insert(list->nodes_dict, node_id, new_node);
  
  return new_node;
}

node_t* node_list_find(node_list_t * list, uint64_t node_id) {
  node_t item;
  item.node_id = node_id;
  return dict_find(list->nodes_dict, node_id);
}