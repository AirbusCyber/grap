#include "graph.hpp"

graph_t* graph_alloc(vsize_t max_size) {
  graph_t* graph;

  graph = (graph_t*) malloc(sizeof(graph_t));
  node_list_build(&graph->nodes, max_size);
  graph->root = NULL;
  return graph;
}

void graph_free(graph_t* graph, bool free_info) {
  if(graph) {
    node_list_free(&(graph->nodes), free_info);
    free(graph);
  }
}

void update_children_fathers_number(graph_t* graph){
  vsize_t k;
  for (k = 0; k < graph->nodes.size; k++){
    graph->nodes.storage[k]->info->childrenNumber = graph->nodes.storage[k]->children_nb;
    graph->nodes.storage[k]->info->fathersNumber = graph->nodes.storage[k]->fathers_nb;
  }
}