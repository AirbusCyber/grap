#ifndef DICT_C
#define DICT_C

#include "dict.hpp"

int compar(const void *l, const void *r) {
  const dictPair *dl = (const dictPair *) l;
  const dictPair *dr = (const dictPair *) r;
  
  if (dl->key < dr->key)
    return -1;
  if (dl->key > dr->key)
    return 1;
  return 0;
}

struct dict *dict_alloc() {
  struct dict *d = (struct dict *) malloc_or_quit(sizeof(dict));
  d->root = NULL;
  return d;
}

node_t *dict_insert(struct dict * d, uint64_t k, node_t * v) {
  dictPair *p = (dictPair*) malloc_or_quit(sizeof(dictPair));
  p->key = k;
  p->value = v;

  const void *r = tsearch(p, &d->root, compar);
  
  if (*(dictPair **) r != p){
//     nothing was added
    free(p);
  }

  return (*(dictPair **) r)->value;
}


node_t *dict_find(struct dict * d, uint64_t k) {
  dictPair *p = (dictPair*) malloc_or_quit(sizeof(dictPair));
  p->key = k;

  dictPair *r = (dictPair *) tfind(p, &d->root, compar);
  free(p);

  if (r == NULL)
    return NULL;
  else
    return (*(dictPair **) r)->value;
}


void dict_delete(struct dict *d, uint64_t k) {
  dictPair *p = (dictPair*) malloc_or_quit(sizeof(dictPair));
  p->key = k;

  tdelete(p, &d->root, compar);
  free(p);
}

void dict_free(struct dict *d) {
  tdestroy(d->root, free);
}

#endif
