#include "node_list.hpp"


void node_list_build(node_list_t * list, vsize_t max_size) {
  list->size = max_size;
  list->count = 0;
  list->storage = NULL;
  list->nodes_map = new std::map < vsize_t, node_t * >();
}

void node_list_add(node_list_t * list, node_t* node) {
  std::map< vsize_t, node_t * >::iterator id_it = list->nodes_map->find(node->node_id);
  
  if (id_it == list->nodes_map->end()){
    // node_id not found: node is a new node in list
    list->size++;
    list->storage = (node_t**) realloc_or_quit(list->storage , list->size * sizeof(node_t*));

    list->storage[list->size-1] = node;
    list->storage[list->size-1]->list_id = list->count;
    list->count++;

    list->nodes_map->insert(std::pair< vsize_t, node_t * >(node->node_id, node));
  }
  else {
    // node already exists
    printf("Warning: node %x already exists in graph (it was NOT duplicated).\n", (int) node->node_id);
  }
}

void node_list_free(node_list_t * list, bool free_info) {
  vsize_t i;

  for (i = 0; i < list->size; i++) {
    node_free(list->storage[i], free_info);
  }
  
  free(list->storage);
  delete list->nodes_map;
}

node_t * node_list_item(const node_list_t * list, vsize_t index) {
  return list->storage[index];
}

vsize_t node_list_size(const node_list_t * list) {
  return list->count;
}

node_t* node_list_append(node_list_t * list, uint64_t node_id) {
  node_t *new_node;

//   MY_ASSERT_MSG(list->count < list->size, "Too small node_list");

  new_node = list->storage[list->count];
  new_node->node_id = node_id;
  new_node->list_id = list->count;
  list->count++;

  list->nodes_map->insert(std::pair< vsize_t, node_t * >(node_id, new_node));
  
  return new_node;
}

node_t* node_list_find(node_list_t * list, uint64_t node_id) {
  node_t item;
  item.node_id = node_id;
  
  std::map< vsize_t, node_t * >::iterator id_it = list->nodes_map->find(node_id);
  if (id_it == list->nodes_map->end()){
    return NULL; 
  }
  else{
    return id_it->second;
  }
}