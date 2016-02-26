#include "graph.hpp"

graph_t* graph_alloc(vsize_t max_size) {
  graph_t* graph;

  graph = (graph_t*) malloc(sizeof(graph_t));
  node_list_build(&graph->nodes, max_size);
  graph->root = NULL;
  return graph;
}

void graph_free(graph_t* graph) {
  if(graph) {
    node_list_free(&(graph->nodes));
    free(graph);
  }
}
