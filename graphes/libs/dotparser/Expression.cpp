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
  e->x = hash_func(f);
  e->y = hash_func(c);
  
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
    std::map< vsize_t, node_t * >::iterator id_it = g->nodes.nodes_map->find(cl->couples[i]->x);
    if (id_it == g->nodes.nodes_map->end()){
      f = NULL; 
    }
    else {
      f = id_it->second;
    }
    
    id_it = g->nodes.nodes_map->find(cl->couples[i]->y);
    if (id_it == g->nodes.nodes_map->end()){
      c = NULL; 
    }
    else {
      c = id_it->second;
    }

    if (f == NULL || c == NULL) {
      printf("WARNING: when adding a node, father or child was not found in graph.\n");
    }
    else {
      node_link(f, c);
    }
  }

  freeEdgeList(cl);
  
  vsize_t k;
  for (k = 0; k < g->nodes.size; k++){
    g->nodes.storage[k]->info->childrenNumber = g->nodes.storage[k]->children_nb;
    g->nodes.storage[k]->info->fathersNumber = g->nodes.storage[k]->fathers_nb;
  }
  
  return g;
}

vsize_t hash_func(char *s) {
  vsize_t h = 0;
  size_t i;

  for (i = 0; i < strlen(s); i++) {
    if (s[i] != '"') {
      h = 131 * h + ((vsize_t) s[i]);
    }
  }
  return h;
}

node_t *createNode(char *value) {
  vsize_t id = hash_func(value);
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
  
  CondNode* cn = new CondNode();
  CondNode** cn_ptr = (CondNode**) malloc(sizeof(CondNode*));
  *cn_ptr = cn;
  n->condition = cn_ptr;
  n->info->lazyRepeat = false;
  bool cond_filled = false;

  for (i = 0; i < ol->size; i++) {
    char *v = removeQuotes(ol->options[i]->value);
    char *id = ol->options[i]->id;

    if (hasSymb == 0 && hasCSymb == 0 && strcmp(id, "label") == 0) {
      n->info->inst_str = v;
    }
    else if (strcmp(id, "cond") == 0 || strcmp(id, "condition") == 0){
      n->condition = CondNodeParser::parseCondNode(std::string(v));
      cond_filled = true;
    }
    else if (strcmp(id, "root") == 0 || (strcmp(id, "fillcolor") == 0 && strcmp(v, "orange") == 0)) {
      n->info->is_root = true;
    }
    else if (strcmp(id, "symb") == 0) {
      hasSymb = 1;
      
      std::cout << "TODO: symb option deprecated\n";
    }
    else if (strcmp(id, "inst") == 0 || strcmp(id, "instruction") == 0 || strcmp(id, "csymb") == 0) {
      hasCSymb = 1;
      
      n->info->inst_str = v;
    }
    else if (strcmp(id, "op") == 0 || strcmp(id, "opcode") == 0) {
      n->info->opcode = v;
    }
    else if (not cond_filled and (strcmp(id, "symbtype") == 0 or strcmp(id, "csymbtype") == 0)) {
      if (strcmp(v, "none") == 0 or strcmp(v, "*") == 0) {        
        (*(n->condition))->comparison = ComparisonFunEnum::bool_true;
        cond_filled = true;
      }
      else if (strcmp(v, "substring") == 0) {        
        (*(n->condition))->pattern_field = (void* NodeInfo::*) &NodeInfo::inst_str;
        (*(n->condition))->test_field = (void* NodeInfo::*) &NodeInfo::inst_str;
        (*(n->condition))->comparison = ComparisonFunEnum::str_contains;
        cond_filled = true;
      }
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
      n->info->get = true;
      n->info->getid = v;
    }
    else if (strcmp(id, "addr") == 0 or strcmp(id, "address") == 0) {
      n->info->has_address = true;
      n->info->address = (vsize_t) strtol(v, NULL, 16);
    }
    
    free(v);
  }

  if (hasMinRepeat && !hasMaxRepeat) {
    n->info->has_maxRepeat = false;
  }
  
  if ((not cond_filled) and n->info->inst_str != ""){
    (*(n->condition))->pattern_field = (void* NodeInfo::*) &NodeInfo::inst_str;
    (*(n->condition))->test_field = (void* NodeInfo::*) &NodeInfo::inst_str;
    (*(n->condition))->comparison = ComparisonFunEnum::str_equals;
  }
  
  if (not n->info->has_address){
    n->info->address = 0; 
  }
  
  if (n->info->opcode == "" and n->info->inst_str != ""){
    std::size_t found = n->info->inst_str.find_first_of(" ");
    if (found!=std::string::npos){
      n->info->opcode = n->info->inst_str.substr(0, found);
    }
    else {
      n->info->opcode = n->info->inst_str;
    }
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
