#include "nodeIO.hpp"

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

  ret = (size_t) fprintf(fp, "\"%" PRIx64 "\" [", node->node_id);
  const char *s = node->info->inst_str.c_str();

  ret += (size_t) fprintf(fp, "symb = ");
  ret += (size_t) fprintf(fp, "%s", s);

  //printing label
  fprintf(fp, ", label = \"%" PRIx64 "(%d) : ", node->node_id, (int) node_number);
  ret += (size_t) fprintf(fp, "%s", "(");
  ret += (size_t) fprintf(fp, "%s", node->info->inst_str.c_str());
  ret += (size_t) fprintf(fp, "%s", ")");

  if (node->info->minRepeat > 1 || !node->info->has_maxRepeat || node->info->maxRepeat > 1) {
    ret += (size_t) fprintf(fp, "{%d,", (int) node->info->minRepeat);

    if (node->info->has_maxRepeat) {
      ret += (size_t) fprintf(fp, "%d}", (int) node->info->maxRepeat);
    }
    else {
      ret += (size_t) fprintf(fp, "}");
    }
  }

  if (node->info->minChildrenNumber > 0) {
    ret += (size_t) fprintf(fp, "(c>=%d)", (int) node->info->minChildrenNumber);
  }
  if (node->info->has_maxChildrenNumber) {
    ret += (size_t) fprintf(fp, "(c<=%d)", (int) node->info->maxChildrenNumber);
  }
  if (node->info->minFathersNumber > 0) {
    ret += (size_t) fprintf(fp, "(f>=%d)", (int) node->info->minFathersNumber);
  }
  if (node->info->has_maxFathersNumber) {
    ret += (size_t) fprintf(fp, "(f<=%d)", (int) node->info->maxFathersNumber);
  }
  ret += (size_t) fprintf(fp, "%s", "\"");

  //printing other props
  if (node->info->minRepeat != 1)
    ret += (size_t) printVKint(fp, (char*) "minrepeat", node->info->minRepeat, 1);
  if (node->info->has_maxRepeat == 1)
    ret += (size_t) printVKint(fp, (char*) "maxrepeat", node->info->maxRepeat, 1);
  if (node->info->lazyRepeat)
    ret += (size_t) fprintf(fp, ", lazyrepeat=true");
  char *str = (char*) malloc(4 * sizeof(char));
  snprintf(str, 4, "%d", node->info->minChildrenNumber);
  ret += (size_t) printVK(fp, (char*) "minchildren", str, 1);
  if (node->info->has_maxChildrenNumber) {
    snprintf(str, 4, "%d", node->info->maxChildrenNumber);
    ret += (size_t) printVK(fp, (char*) "maxchildren", str, 1);
  }
  snprintf(str, 4, "%d", node->info->minFathersNumber);
  ret += (size_t) printVK(fp, (char*) "minfathers", str, 1);
  if (node->info->has_maxFathersNumber) {
    snprintf(str, 4, "%d", node->info->maxFathersNumber);
    ret += (size_t) printVK(fp, (char*) "maxfathers", str, 1);
  }
  free(str);

  if (node == root)
    ret += (size_t) fprintf(fp, ", style=\"bold,filled\", fillcolor=yellow]\n");
  else
    ret += (size_t) fprintf(fp, "]\n");

  return ret;
}

size_t node_edges_to_dot(const node_t * node, FILE * fp) {
  size_t j;
  size_t ret;

  ret = 0;
  for (j = 0; j < node->children_nb; ++j) {
    const node_t *child = node_child_const(node, j);
    ret += (size_t) fprintf(fp, "\"%" PRIx64 "\" -> \"%" PRIx64 "\" [label = \"%" PRIx64 "\"]", node->node_id, child->node_id, j);
    ret += (size_t) fprintf(fp, "\n");
  }
  return ret;
}
