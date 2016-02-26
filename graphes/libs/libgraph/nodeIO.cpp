#include "nodeIO.h"

int printVK(FILE * fp, char *key, char *value, char virg) {
  if (virg)
    return fprintf(fp, ", %s = \"%s\"", key, value);
  else
    return fprintf(fp, "%s = \"%s\"", key, value);
}

int printVKint(FILE * fp, char *key, int value, char virg) {
  if (virg)
    return fprintf(fp, ", %s = \"%d\"", key, value);
  else
    return fprintf(fp, "%s = \"%d\"", key, value);
}

size_t node_to_dot(const node_t * node, const node_t * root, size_t node_number, FILE * fp) {
  size_t ret;

  ret = fprintf(fp, "\"%" PRIx64 "\" [", node->node_id);
  char *s = (char*) node->info->inst_str.c_str();

  ret += fprintf(fp, "symb = ");
  ret += fprintf(fp, "%s", s);

  //printing label
  fprintf(fp, ", label = \"%" PRIx64 "(%d) : ", node->node_id, (int) node_number);
  ret += fprintf(fp, "%s", "(");
  ret += fprintf(fp, "%s", node->info->inst_str.c_str());
  ret += fprintf(fp, "%s", ")");

  if (node->info->minRepeat > 1 || !node->info->has_maxRepeat || node->info->maxRepeat > 1) {
    ret += fprintf(fp, "{%d,", node->info->minRepeat);

    if (node->info->has_maxRepeat) {
      ret += fprintf(fp, "%d}", node->info->maxRepeat);
    }
    else {
      ret += fprintf(fp, "}");
    }
  }

  if (node->info->minChildrenNumber > 0) {
    ret += fprintf(fp, "(c>=%d)", node->info->minChildrenNumber);
  }
  if (node->info->has_maxChildrenNumber) {
    ret += fprintf(fp, "(c<=%d)", node->info->maxChildrenNumber);
  }
  if (node->info->minFathersNumber > 0) {
    ret += fprintf(fp, "(f>=%d)", node->info->minFathersNumber);
  }
  if (node->info->has_maxFathersNumber) {
    ret += fprintf(fp, "(f<=%d)", node->info->maxFathersNumber);
  }
  ret += fprintf(fp, "%s", "\"");

  //printing other props
  if (node->info->minRepeat != 1)
    ret += printVKint(fp, (char*) "minrepeat", node->info->minRepeat, 1);
  if (node->info->has_maxRepeat == 1)
    ret += printVKint(fp, (char*) "maxnrepeat", node->info->maxRepeat, 1);
  char *str = (char*) malloc(4 * sizeof(char));
  snprintf(str, 4, "%d", node->info->minChildrenNumber);
  ret += printVK(fp, (char*) "minchildren", str, 1);
  if (node->info->has_maxChildrenNumber) {
    snprintf(str, 4, "%d", node->info->maxChildrenNumber);
    ret += printVK(fp, (char*) "maxchildren", str, 1);
  }
  snprintf(str, 4, "%d", node->info->minFathersNumber);
  ret += printVK(fp, (char*) "minfathers", str, 1);
  if (node->info->has_maxFathersNumber) {
    snprintf(str, 4, "%d", node->info->maxFathersNumber);
    ret += printVK(fp, (char*) "maxfathers", str, 1);
  }
  free(str);

  if (node == root)
    ret += fprintf(fp, ", style=\"bold,filled\", fillcolor=yellow]\n");
  else
    ret += fprintf(fp, "]\n");

  return ret;
}

size_t node_edges_to_dot(const node_t * node, FILE * fp) {
  vsize_t j;
  size_t ret;

  ret = 0;
  for (j = 0; j < node->children_nb; ++j) {
    const node_t *child = node_child_const(node, j);
    ret += fprintf(fp, "\"%" PRIx64 "\" -> \"%" PRIx64 "\" [label = \"%d\"]", node->node_id, child->node_id, j);
    ret += fprintf(fp, "\n");
  }
  return ret;
}
