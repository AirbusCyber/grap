/*
 * Expression.c
 * Implementation of functions used to build the syntax tree.
 */

#include "Expression.hpp"

void debug_print(char *s) {
  if (0 == 1)
    printf("%s", s);
}

CoupleList *createEdgeList() {
  CoupleList *cl = (CoupleList *) malloc_or_quit(sizeof(CoupleList));
  cl->size = 0;
  cl->couples = NULL;

  return cl;
}

CoupleList *addEdgeToList(Couple * c, CoupleList * cl) {
  cl->couples = (Couple **) realloc_or_quit(cl->couples, (cl->size + 1) * sizeof(Couple *));
  cl->couples[cl->size] = c;
  cl->size++;

  return cl;
}

void freeEdgeList(CoupleList* cl){
  vsize_t i;
  for (i = 0; i < cl->size; i++){
    free(cl->couples[i]);
  }
  
  free(cl->couples);
  free(cl);
}

Couple *createEdge(char *f, char *c, OptionList* ol) {
  Couple *e = (Couple *) malloc_or_quit(sizeof(Couple));
  e->x = hash(f);
  e->y = hash(c);
  
  free(f);
  free(c);
  
  if (ol != NULL) freeOptionList(ol);
  return e;
}

graph_t *addEdgesToGraph(CoupleList * cl, graph_t * g) {
  int i;
  node_t *f;
  node_t *c;

  for (i = cl->size - 1; i >= 0; i--) {
    f = dict_find(g->nodes.nodes_dict, cl->couples[i]->x);
    c = dict_find(g->nodes.nodes_dict, cl->couples[i]->y);

    if (f == NULL || c == NULL) {
      printf("WARNING: when adding a node, father or child was not found in graph.\n");
    }
    else {
      node_link(f, c);
    }
  }

  freeEdgeList(cl);
  return g;
}

uint hash(char *s) {
  uint h = 0;
  size_t i;

  for (i = 0; i < strlen(s); i++) {
    if (s[i] != '"') {
      h = 131 * h + ((uint) s[i]);
    }
  }
  return h;
}

node_t *createNode(char *value) {
  uint id = hash(value);
  free(value);

  node_t *node = (node_t *) calloc_or_quit(1, sizeof(node_t));
  node->children = NULL;
  node->fathers = NULL;
  node->children_nb = 0;
  node->fathers_nb = 0;
  node->list_id = 0;
  node->node_id = id;
  node->info = new NodeInfo();

  return node;
}

graph_t *createGraph() {
  graph_t *graph = NULL;
  graph = graph_alloc(0);
  
  return graph;
}

graph_t *addNodeToGraph(node_t * n, graph_t * g) {
  node_list_add(&g->nodes, n);
  node_t *r = dict_find(g->nodes.nodes_dict, n->node_id);

  if (g->nodes.size == 1 || n->info->is_root)
    g->root = n;
  
  return g;
}

char *removeQuotes(char *s) {
  char *s2 = (char *) malloc_or_quit((strlen(s) + 1) * sizeof(char));
  size_t i;
  size_t k = 0;

  for (i = 0; i < strlen(s); i++) {
    if (s[i] != '"') {
      s2[k] = s[i];
      k++;
    }
  }
  s2[k] = 0;

  return s2;
}

node_t *updateNode(OptionList * ol, node_t * n) {
  size_t i;
  char hasSymb = 0;
  char hasCSymb = 0;
  char hasMinRepeat = 0;
  char hasMaxRepeat = 0;
  
  n->condition = new CondNode();
  n->info->lazyRepeat = false;
  bool cond_filled = false;

  for (i = 0; i < ol->size; i++) {
    char free_v = 1;
    char *v = removeQuotes(ol->options[i]->value);
    char *id = ol->options[i]->id;

    if (hasSymb == 0 && hasCSymb == 0 && strcmp(id, "label") == 0) {
      
      free_v = 0;
      n->info->inst_str = v;
    }
    else if (strcmp(id, "root") == 0 || (strcmp(id, "fillcolor") == 0 && strcmp(v, "orange") == 0)) {
      n->info->is_root = true;
    }
    else if (strcmp(id, "symb") == 0) {
      hasSymb = 1;
      
      std::cout << "TODO: symb option deprecated\n";
    }
    else if (strcmp(id, "csymb") == 0) {
      free_v = 0;
      hasCSymb = 1;
      
      n->info->inst_str = v;
    }
    else if (strcmp(id, "symbtype") == 0 || strcmp(id, "csymbtype") == 0) {
      if (strcmp(v, "none") == 0 || strcmp(v, "*") == 0) {        
        n->condition->comparison = ComparisonFunEnum::bool_true;
        cond_filled = true;
      }
      
//       TODO: generic opcode
//       else if (strcmp(v, "generic") == 0 || strcmp(v, "gopcode") == 0) {
//         n->csymbType = LABEL_GENERIC_OPCODE;
//         
//         n->condition->pattern_field = (void* NodeInfo::*) &NodeInfo::inst_str;
//         n->condition->test_field = (void* NodeInfo::*) &NodeInfo::inst_str;
//         n->condition->comparison = ComparisonFunctions::str_equals();
//       }

//       TODO: opcode
//       else if (strcmp(v, "opcode") == 0) {
//         n->csymbType = LABEL_EXACT_OPCODE;
//       }
//       else if (strcmp(v, "string") == 0) {
//         n->csymbType = LABEL_EXACT_STRING;
//       }

      else if (strcmp(v, "substring") == 0) {        
        n->condition->pattern_field = (void* NodeInfo::*) &NodeInfo::inst_str;
        n->condition->test_field = (void* NodeInfo::*) &NodeInfo::inst_str;
        n->condition->comparison = ComparisonFunEnum::str_contains;
        cond_filled = true;
      }
      
//       TODO: regex
//       else if (strcmp(v, "regex") == 0) {
//         n->csymbType = LABEL_REGEX;
//       }

    }
    else if (strcmp(id, "repeat") == 0) {
      if (strcmp(v, "*") == 0) {        
        n->info->minRepeat = 0;
        n->info->has_maxRepeat = false;
      }
      else if (strcmp(v, "+") == 0) {
        n->info->minRepeat = 1;
        n->info->has_maxRepeat = false;
      }
      else if (strcmp(v, "++") == 0) {
        n->info->minRepeat = 2;
        n->info->has_maxRepeat = false;
      }
      else {
        n->info->minRepeat = 1;
        n->info->has_maxRepeat = true;
        n->info->maxRepeat = 1;
      }
    }
    else if (strcmp(id, "minrepeat") == 0) {
      hasMinRepeat = 1;
      n->info->minRepeat = (vsize_t) atoi(v);
    }
    else if (strcmp(id, "maxrepeat") == 0) {
      hasMaxRepeat = 1;
      n->info->has_maxRepeat = true;
      n->info->maxRepeat = (vsize_t) atoi(v);
    }
    else if (strcmp(id, "lazyrepeat") == 0){
      if (strcmp(v, "true") == 0){
        n->info->lazyRepeat = true;
      }
      else{
        n->info->lazyRepeat = false;
      }
    }
    else if (strcmp(id, "minchildren") == 0) {
      n->info->minChildrenNumber = (vsize_t) atoi(v);
    }
    else if (strcmp(id, "maxchildren") == 0) {
      n->info->has_maxChildrenNumber = true;
      n->info->maxChildrenNumber = (vsize_t) atoi(v);
    }
    else if (strcmp(id, "minfathers") == 0) {
      n->info->minFathersNumber = (vsize_t) atoi(v);
    }
    else if (strcmp(id, "maxfathers") == 0) {
      n->info->has_maxFathersNumber = true;
      n->info->maxFathersNumber = (vsize_t) atoi(v);
    }
    else if (strcmp(id, "getid") == 0) {
      free_v = 0;
      
      n->info->get = true;
      n->info->getid = v;
    }
    else if (strcmp(id, "address") == 0) {
      n->info->has_address = true;
      n->info->address = (vsize_t) strtol(v, NULL, 16);
    }
    
    if (free_v) free(v);
  }

  if (hasMinRepeat && !hasMaxRepeat) {
    n->info->has_maxRepeat = false;
  }
  
  if ((not cond_filled) and n->info->inst_str != ""){
    n->condition->pattern_field = (void* NodeInfo::*) &NodeInfo::inst_str;
    n->condition->test_field = (void* NodeInfo::*) &NodeInfo::inst_str;
    n->condition->comparison = ComparisonFunEnum::str_equals;
  }

  freeOptionList(ol);
  return n;
}

OptionList *createOptionList() {
  OptionList *ol = (OptionList *) malloc_or_quit(sizeof(OptionList));
  ol->size = 0;
  ol->options = NULL;

  return ol;
}

OptionList *addOptionToList(Option * o, OptionList * ol) {
  ol->options = (Option **) realloc_or_quit(ol->options, (ol->size + 1) * sizeof(Option *));
  ol->options[ol->size] = o;
  ol->size++;

  return ol;
}

Option *createOption(char *I, char *V) {
  Option *o = (Option *) malloc_or_quit(sizeof(Option));

  char *key = (char *) malloc_or_quit((strlen(I) + 1) * sizeof(char));
  strcpy(key, I);

  char *value = (char *) malloc_or_quit((strlen(V) + 1) * sizeof(char));
  strcpy(value, V);

  o->id = key;
  o->value = value;
  
  free(I);
  free(V);
  
  return o;
}

void freeOption(Option * o) {
  free(o->id);
  free(o->value);
  free(o);
}

void freeOptionList(OptionList * ol) {
  vsize_t i;
  for (i = 0; i < ol->size; i++) {
    freeOption(ol->options[i]);
  }
  
  free(ol->options);
  free(ol);
}
