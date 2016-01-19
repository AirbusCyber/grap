#include "graphIO.h"

size_t graph_to_file(graph_t* graph, FILE* fp) {
  struct node_list_iterator_t* node_it;
  size_t ret, count;
  node_t* node;
  vsize_t nNonOrphanNode=0;

  ret = 0;

  /* Write Magic value */
  ret += fwrite_le_swap(GRAPHBINMAGIC, 1, GRAPHBINMAGIC_LEN, fp);

  size_t i;
  
  /* write the number of nodes */
  /* only taking non orphans nodes */
  for (i=0; i<graph->nodes.count; i++){
    node_t* node = &(graph->nodes.storage[i]);
    if (node->children_nb!=0 || node->fathers_nb!=0){
      nNonOrphanNode++;
    }
  }

  count = fwrite_le_swap(&nNonOrphanNode, sizeof(vsize_t), 1, fp);
  ret += count * sizeof(vsize_t);

  /* for easier parsing all node are dumped first */
  for (i=0; i<graph->nodes.count; i++){
    node_t* node = &(graph->nodes.storage[i]);
    if (node->children_nb != 0 || node ->fathers_nb != 0){
	    fputc('n', fp);
	    ret++;
	    nNonOrphanNode++;

	    ret += node_to_file(node, fp);
    }
  }

  /* then edges */
  for (i=0; i<graph->nodes.count; i++){
    node_t* node = &(graph->nodes.storage[i]);
    ret += node_edges_to_file(node, fp);
  }

  if (nNonOrphanNode != 0 && graph->root != NULL){
	  fputc('r', fp);
	  ret++;

	  count = fwrite_le_swap(&graph->root->node_id, sizeof(graph->root->node_id), 1, fp);
	  ret += count * sizeof(graph->root->node_id);
  }

  return ret;
}

status_t graph_from_file(graph_t** pgraph, FILE* fp) {  
  node_t* node, *new_node;
  vsize_t count;
  graph_t * graph = NULL;
  char magic[GRAPHBINMAGIC_LEN];
  char c;

  node = node_alloc();

  /* Check Magic value */
  fread_le_swap(magic, 1, GRAPHBINMAGIC_LEN, fp);
  if (strncmp(magic, GRAPHBINMAGIC, GRAPHBINMAGIC_LEN)){
    goto broken_file;
	}

  if (fread_le_swap(&count, sizeof(vsize_t), 1, fp) != 1){
	  goto broken_file;
  }

  graph = graph_alloc(count);
  *pgraph = graph;

  while ((c = fgetc(fp)) && !feof(fp)) {
    switch (c) {
    case 'n':
      /* it's a node */
      node_from_file(node, fp);
      new_node = node_list_append(&graph->nodes, node->node_id);
      new_node->symb = node->symb;
      break;

    case 'e': {
      /* it's an edge */
      uint64_t node_id;
      node_t *child, *father;

      if (fread_le_swap(&node_id, sizeof(uint64_t), 1, fp) != 1){
    	  goto broken_file;
      }

      father = node_list_find(&graph->nodes, node_id);

      if (father == NULL){
    	  goto broken_file;
      }

      if (fread_le_swap(&node_id, sizeof(uint64_t), 1, fp) != 1){
    	  goto broken_file;
      }

      child = node_list_find(&graph->nodes, node_id);

//		printf("%x %d\n", node_id, node_id);
      if (child == NULL){
    	  goto broken_file;
      }

      node_link(father, child);
      break;
    }
    case 'r': {
      /* it's the root node */
      uint64_t node_id;
      node_t *root;

      if (fread_le_swap(&node_id, sizeof(graph->root->node_id), 1, fp) != 1){
    	  goto broken_file;
      }


      root = node_list_find(&graph->nodes, node_id);

//      if (root == 0){
//    	  fprintf(stderr, "Root node has address zero (0)\n");
//    	  goto broken_file;
//      }

      graph->root = root;
      break;
    }
    default:
    	goto broken_file;
    }
  }

/*  if(!feof(fp)){
	printf("B8");
	goto broken_file;
  }*/

  node_free(node);
//   graph_fprint(stdout, graph);
  return STATUS_OK;

  broken_file:
  node_free(node);
  graph_free(graph);
  
  rewind(fp);
  *pgraph = (graph_t*) getGraphFromFile(fp);
  
  if (*pgraph != NULL) return STATUS_OK;
  fprintf(stderr, "graph dump file is broken\n");

  return STATUS_INVALID_FILE;
}

//void checkChildrenFathers(graph_t* graph){
//	struct node_list_iterator_t* node_it;
//	node_t* node;
//	node_t* child;
//	node_t* father;
//	node_it = node_list_it_new(&graph->nodes);
//	vsize_t i;
//	vsize_t j;
//	char found;
//
//	while ((node = node_list_it_get_next(node_it)) != NULL) {
//		for (i=0; i<node->children_nb; i++){
//			found=0;
//			child=node->children[i];
//
////			fprintf(stderr, "%d: %d fathers\n", child->node_id, child->fathers_nb);
//
//			for (j=0; j<child->fathers_nb; j++){
//				father=child->fathers[j];
////				fprintf(stderr, "father: %d\n", father->node_id);
//
//				if (father==node){
//					found=1;
//					break;
//				}
//			}
//
//			if (found==0) fprintf(stderr, "%d, Souci: father not found.\n", child->node_id);
//		}
//	}
//}

int is_graphbin_file (FILE* fp) {
  char magic[GRAPHBINMAGIC_LEN];

  if (fseek(fp, 0L, SEEK_SET) != 0)
    goto not_graph;
  if (fread_le_swap(magic, 1, GRAPHBINMAGIC_LEN, fp) != GRAPHBINMAGIC_LEN)
    goto not_graph;
  if (strncmp(magic, GRAPHBINMAGIC, GRAPHBINMAGIC_LEN) != 0)
    goto not_graph;

  rewind(fp);
  return 1;

  not_graph:
  rewind(fp);
  return 0;
}

void graph_fprint(FILE* fp, graph_t* graph) {
  struct node_list_iterator_t *node_it;
  node_t* node;

  fprintf(fp, "Digraph G {\n");

  size_t i;
  
  for (i=0; i<graph->nodes.count; i++){
      node_t node = graph->nodes.storage[i];
	  node_to_dot(&node,(node_t*)&graph->root->node_id, i, fp);
	  node_edges_to_dot(&node, fp);
  }


  fprintf(fp, "}\n");
}
