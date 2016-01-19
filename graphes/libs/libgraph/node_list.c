#include "node_list.h"


void node_list_build(node_list_t * list, vsize_t max_size) {
  list->size = max_size;
  list->count = 0;
  list->storage = MY_ZALLOC(max_size, node_t);
  list->nodes_dict = dict_alloc();
}

void node_list_add(node_list_t * list, node_t* node) {
  node_t* r = dict_find(list->nodes_dict, node->node_id);
  
  if (r == NULL){
    // new node
    list->size++;
    list->storage = (node_t*) realloc(list->storage , list->size * sizeof(node_t));

    list->storage[list->size-1] = *node;
    list->storage[list->size-1].list_id = list->count;
    list->count++;

    node_t* rr = dict_insert(list->nodes_dict, node->node_id, &list->storage[list->size-1]);
  }
  else {
    // node already exists 
    printf("Warning: node %x already exists in graph (it was NOT duplicated).\n", node->node_id);
  }
}

void node_list_free(node_list_t * list) {
  vsize_t i;
  for (i = 0; i < list->size; i++) {
    MY_FREE(list->storage[i].children);
    MY_FREE(list->storage[i].fathers);
  }
  MY_FREE(list->storage);
  dict_free(list->nodes_dict);
}

void node_list_reset(node_list_t * list) {
  vsize_t i;
  for (i = 0; i < list->count; i++) {
    node_reset(&list->storage[i]);
  }
  list->count = 0;
  dict_free(list->nodes_dict);
  list->nodes_dict = dict_alloc();
}

node_t * node_list_item(const node_list_t * list, vsize_t index) {
  return &list->storage[index];
}

void node_list_set_all_unexplored(node_list_t * list) {
  vsize_t i;
  for (i = 0; i < list->count; i++) {
    list->storage[i].explored = UNEXPLORED;
  }
}

vsize_t node_list_size(const node_list_t * list) {
  return list->count;
}

vsize_t node_list_size_reduc(const node_list_t * list) {
  vsize_t index,Node_count;

  Node_count=0;
  for (index = 0; index < node_list_size(list); ++index) {
	    node_t* node = node_list_item(list, index);
	    if (node->fathers_nb ==0 && node->children_nb ==0)
	    	continue;
	    Node_count++;
   }
  return Node_count;
}

node_t* node_list_append(node_list_t * list, uint64_t node_id) {
  node_t *new_node;

  MY_ASSERT_MSG(list->count < list->size, "Too small node_list");

  new_node = &list->storage[list->count];
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