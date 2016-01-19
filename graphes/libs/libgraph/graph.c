#include "graph.h"

graph_t* graph_alloc(vsize_t max_size) {
  graph_t* graph;

  graph = MY_MALLOC(1, graph_t);
  node_list_build(&graph->nodes, max_size);
  graph->root = NULL;
  graph->version = 1;
  return graph;
}

void graph_free(graph_t* graph) {
  if(graph) {
    node_list_free(&graph->nodes);
    MY_FREE(graph);
  }
}

void graph_reset(graph_t* graph) {
  graph->root = NULL;
  node_list_reset(&graph->nodes);
}
