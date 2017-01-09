#include "graphIO.hpp"

void graph_fprint(FILE* fp, graph_t* graph) {
  struct node_list_iterator_t *node_it;

  if (graph != nullptr){
    fprintf(fp, "Digraph G {\n");

    size_t i;
    
    for (i=0; i<graph->nodes.count; i++){
      node_t* node = graph->nodes.storage[i];
      node_to_dot(node,(node_t*)&graph->root->node_id, i, fp);
    }
    
    for (i=0; i<graph->nodes.count; i++){
      node_t* node = graph->nodes.storage[i];
      node_edges_to_dot(node, fp);
    }


    fprintf(fp, "}\n");
  }
}

void graph_save_to_path(std::string path, graph_t * graph){
  FILE* fp = fopen(path.c_str(), "wb");
  if (fp != nullptr){
    graph_fprint(fp, graph);
    fclose(fp);
  }
}