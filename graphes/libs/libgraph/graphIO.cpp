#include "graphIO.hpp"

void graph_fprint(FILE* fp, graph_t* graph) {
  struct node_list_iterator_t *node_it;

  fprintf(fp, "Digraph G {\n");

  size_t i;
  
  for (i=0; i<graph->nodes.count; i++){
    node_t* node = graph->nodes.storage[i];
    node_to_dot(node,(node_t*)&graph->root->node_id, i, fp);
    node_edges_to_dot(node, fp);
  }


  fprintf(fp, "}\n");
}
