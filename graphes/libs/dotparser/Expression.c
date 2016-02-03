/*
 * Expression.c
 * Implementation of functions used to build the syntax tree.
 */

#include "Expression.h"

#include <stdlib.h>
#include <stdio.h>

void debug_print(char *s) {
  if (0 == 1)
    printf("%s", s);
}

CoupleList *createEdgeList() {
  CoupleList *cl = (CoupleList *) malloc(sizeof(CoupleList));
  cl->size = 0;
  cl->couples = NULL;

  return cl;
}

CoupleList *addEdgeToList(Couple * c, CoupleList * cl) {
  cl->couples = (Couple **) realloc(cl->couples, (cl->size + 1) * sizeof(Couple *));
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
  Couple *e = (Couple *) malloc(sizeof(Couple));
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
//      int k;
//      for (k=0; k<g->nodes.size; k++){
//        printf("%d: %p\n", k, &g->nodes.storage[k]);  
//      }

//      printf("linking\n");
      node_link(f, c);
//      printf("%p (%x) != %p (%x)\n", f, f->node_id, &g->nodes.storage[0], (&g->nodes.storage[0])->node_id);
//      node_link(&g->nodes.storage[0], c);
    }
  }

//   graph_fprint(stdout, g);
  freeEdgeList(cl);
  return g;
}

uint hash(char *s) {
  uint h = 0;
  int i;

  for (i = 0; i < strlen(s); i++) {
    if (s[i] != '"') {
      h = 131 * h + s[i];
    }
  }
  return h;
}

node_t *createNode(char *value) {
  uint id = hash(value);
  free(value);

  node_t *node = (node_t *) calloc(1, sizeof(node_t));
  node->children = NULL;
  node->fathers = NULL;
  node->children_nb = 0;
  node->fathers_nb = 0;
  node->explored = UNEXPLORED;
  node->list_id = 0;
  node->node_id = id;
  node->symb = INST_SEQ;
  node->version = 1;
  node->csymbType = LABEL_EXACT_STRING;
  node->csymb = NULL;
  node->hasMaxChildrenNumber = 0;
  node->hasMaxFathersNumber = 0;
  node->minChildrenNumber = 0;
  node->minFathersNumber = 0;
  node->get = 0;
  node->getid = NULL;
  node->minRepeat = 1;
  node->hasMaxRepeat = 1;
  node->maxRepeat = 1;
  node->hasAddress = 0;
  node->isRoot = 0;

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

  if (g->nodes.size == 1 || n->isRoot)
    g->root = n;
  
//   printf("new node: %x %x\n", n->node_id, n->address);

  if (n->version == 2)
    g->version = 2;

//   node_to_dot(n,(node_t*)&g->root->node_id, n->node_id, stdout);
  return g;
}

char *removeQuotes(char *s) {
  char *s2 = (char *) malloc((strlen(s) + 1) * sizeof(char));
  int i;
  int k = 0;

  for (i = 0; i < strlen(s); i++) {
    if (s[i] != '"') {
      s2[k] = s[i];
      k++;
    }
  }
  s2[k] = 0;

  return s2;
}

int strToSymb(char *st) {
  char *s = st;
  int r;

  if (strcmp(s, "INIT") == 0) {
    r = SYMB_INIT;
  }
  else if (strcmp(s, "RET") == 0) {
    r = INST_RET;
  }
  else if (strcmp(s, "CALL") == 0) {
    r = INST_CALL;
  }
  else if (strcmp(s, "JMP") == 0 || strcmp(s, "JUMP") == 0) {
    r = INST_JMP;
  }
  else if (strcmp(s, "END") == 0) {
    r = INST_END;
  }
  else if (strcmp(s, "SCALL") == 0) {
    r = INST_SCALL;
  }
  else if (strcmp(s, "UREACH") == 0) {
    r = INST_UREACH;
  }
  else if (strcmp(s, "UNDEF") == 0) {
    r = INST_UNDEF;
  }
  else if (strcmp(s, "JCC") == 0) {
    r = INST_JCC;
  }
  else if (strcmp(s, "SEQ") == 0 || strcmp(s, "INST") == 0) {
    r = INST_SEQ;
  }
  else if (strcmp(s, "PATH") == 0) {
    r = SYMB_PATH;
  }
  else if (strcmp(s, "END") == 0) {
    r = INST_END;
  }
  else {
    r = -1;
  }
  return r;
}

node_t *updateNode(OptionList * ol, node_t * n) {
  int i;
  char hasSymb = 0;
  char hasCSymb = 0;
  char hasMinRepeat = 0;
  char hasMaxRepeat = 0;

  for (i = 0; i < ol->size; i++) {
    char free_v = 1;
    char *v = removeQuotes(ol->options[i]->value);
    char *id = ol->options[i]->id;

    if (hasSymb == 0 && strcmp(id, "label") == 0) {
      n->symb = strToSymb(v);
    }    
    else if (strcmp(id, "root") == 0 || (strcmp(id, "fillcolor") == 0 && strcmp(v, "orange") == 0)) {
      n->isRoot = 1;
    }
    else if (strcmp(id, "symb") == 0) {
      n->symb = strToSymb(v);
      hasSymb = 1;
    }
    else if (strcmp(id, "csymb") == 0) {
      n->version = 2;
      n->csymb = v;
      free_v = 0;
      hasCSymb = 1;
    }
    else if (strcmp(id, "symbtype") == 0 || strcmp(id, "csymbtype") == 0) {
      n->version = 2;
      n->csymbType = LABEL_EXACT_STRING;

      if (strcmp(v, "none") == 0 || strcmp(v, "*") == 0) {
        n->csymbType = LABEL_STAR;
      }
      else if (strcmp(v, "generic") == 0 || strcmp(v, "gopcode") == 0) {
        n->csymbType = LABEL_GENERIC_OPCODE;
      }
      else if (strcmp(v, "opcode") == 0) {
        n->csymbType = LABEL_EXACT_OPCODE;
      }
      else if (strcmp(v, "string") == 0) {
        n->csymbType = LABEL_EXACT_STRING;
      }
      else if (strcmp(v, "substring") == 0) {
        n->csymbType = LABEL_SUBSTRING;
      }
      else if (strcmp(v, "regex") == 0) {
        n->csymbType = LABEL_REGEX;
      }
    }
    else if (strcmp(id, "repeat") == 0) {
      n->version = 2;
      if (strcmp(v, "+") == 0) {
        n->minRepeat = 1;
        n->hasMaxRepeat = 0;
      }
      else if (strcmp(v, "*") == 0) {
        n->minRepeat = 0;
        n->hasMaxRepeat = 0;
      }
      else {
        n->minRepeat = 1;
        n->hasMaxRepeat = 1;
        n->maxRepeat = 1;
      }
    }
    else if (strcmp(id, "minrepeat") == 0) {
      hasMinRepeat = 1;
      n->version = 2;
      n->minRepeat = atoi(v);
    }
    else if (strcmp(id, "maxrepeat") == 0) {
      hasMaxRepeat = 1;
      n->version = 2;
      n->hasMaxRepeat = 1;
      n->maxRepeat = atoi(v);
    }
    else if (strcmp(id, "minchildren") == 0) {
      n->version = 2;
      n->minChildrenNumber = atoi(v);
    }
    else if (strcmp(id, "maxchildren") == 0) {
      n->version = 2;
      n->hasMaxChildrenNumber = 1;
      n->maxChildrenNumber = atoi(v);
    }
    else if (strcmp(id, "minfathers") == 0) {
      n->version = 2;
      n->minFathersNumber = atoi(v);
    }
    else if (strcmp(id, "maxfathers") == 0) {
      n->version = 2;
      n->hasMaxFathersNumber = 1;
      n->maxFathersNumber = atoi(v);
    }
    else if (strcmp(id, "getid") == 0) {
      n->get = 1;
      n->getid = v;
      free_v = 0;
    }
    else if (strcmp(id, "address") == 0) {
      n->hasAddress = 1;
      n->address = (vsize_t) strtol(v, NULL, 16);
    }
    
    if (free_v) free(v);
  }

  if (hasMinRepeat && !hasMaxRepeat) {
    n->hasMaxRepeat = 0;
  }

  if (n->version == 2 && !hasSymb && !hasCSymb) {
    n->csymb = symbToString(n->symb);
  }

  freeOptionList(ol);
  return n;
}

OptionList *createOptionList() {
  OptionList *ol = (OptionList *) malloc(sizeof(OptionList));
  ol->size = 0;
  ol->options = NULL;

  return ol;
}

OptionList *addOptionToList(Option * o, OptionList * ol) {
  ol->options = (Option **) realloc(ol->options, (ol->size + 1) * sizeof(Option *));
  ol->options[ol->size] = o;
  ol->size++;

  return ol;
}

Option *createOption(char *I, char *V) {
  Option *o = (Option *) malloc(sizeof(Option));

  char *key = (char *) malloc((strlen(I) + 1) * sizeof(char));
  strcpy(key, I);

  char *value = (char *) malloc((strlen(V) + 1) * sizeof(char));
  strcpy(value, V);

  o->id = key;
  o->value = value;
  
  free(I);
  free(V);
  
  return o;
}

void freeOption(Option * o) {
//   printf("free %s(%p): %s(%p)\n", o->id, o->id, o->value, o->value);
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
