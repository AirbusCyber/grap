#include "nodeIO.hpp"

int printVK(FILE *fp, char *key, char *value, char virg)
{
  if (virg)
    return fprintf(fp, ", %s = \"%s\"", key, value);
  else
    return fprintf(fp, "%s = \"%s\"", key, value);
}

int printVKint(FILE *fp, char *key, int value, char virg)
{
  if (virg)
    return fprintf(fp, ", %s = \"%d\"", key, value);
  else
    return fprintf(fp, "%s = \"%d\"", key, value);
}

size_t node_to_dot(const node_t *node, const node_t *root, size_t node_number,
                   FILE *fp)
{
  size_t ret;
  
  if (sizeof(vsize_t) >= 8){
    ret = (size_t)fprintf(fp, "\"%" PRIx64 "\" [", node->node_id);
  }
  else {
    // Typically: vsize_t on a 32 bits machine
    ret = (size_t)fprintf(fp, "\"%x\" [", (int32_t) node->node_id);
  }

  const char *s = node->info->inst_str.c_str();
  ret += (size_t)fprintf(fp, "inst=\"");
  ret += (size_t)fprintf(fp, "%s", s);
  ret += (size_t)fprintf(fp, "\", ");

  if (sizeof(vsize_t) >= 8){
    ret += (size_t)fprintf(fp, "address=\"0x%" PRIx64 "\", ", node->info->address);
  }
  else {
    // Typically: vsize_t on a 32 bits machine
    ret += (size_t)fprintf(fp, "address=\"0x%x\", ", (int32_t) node->info->address);
  }  

  // printing label
  ret += (size_t)fprintf(fp, "%s", "label=\"");
  ret += (size_t)fprintf(fp, "%s", node->info->inst_str.c_str());

  if (node->info->minRepeat > 1 || !node->info->has_maxRepeat
      || node->info->maxRepeat > 1) {
    ret += (size_t)fprintf(fp, "{%zu,", node->info->minRepeat);

    if (node->info->has_maxRepeat) {
      ret += (size_t)fprintf(fp, "%zu}", node->info->maxRepeat);
    }
    else {
      ret += (size_t)fprintf(fp, "}");
    }
  }

  if (node->info->minChildrenNumber > 0) {
    ret += (size_t)fprintf(fp, "(c>=%zu)", node->info->minChildrenNumber);
  }
  if (node->info->has_maxChildrenNumber) {
    ret += (size_t)fprintf(fp, "(c<=%zu)", node->info->maxChildrenNumber);
  }
  if (node->info->minFathersNumber > 0) {
    ret += (size_t)fprintf(fp, "(f>=%zu)", node->info->minFathersNumber);
  }
  if (node->info->has_maxFathersNumber) {
    ret += (size_t)fprintf(fp, "(f<=%zu)", node->info->maxFathersNumber);
  }
  ret += (size_t)fprintf(fp, "%s", "\"");

  // printing other props
  if (node->info->minRepeat != 1)
    ret +=
        (size_t)printVKint(fp, (char *)"minrepeat", node->info->minRepeat, 1);
  if (node->info->has_maxRepeat == 1)
    ret +=
        (size_t)printVKint(fp, (char *)"maxrepeat", node->info->maxRepeat, 1);
  if (node->info->lazyRepeat) ret += (size_t)fprintf(fp, ", lazyrepeat=true");
  char *str = (char *)malloc(4 * sizeof(char));
  snprintf(str, 4, "%zu", node->info->minChildrenNumber);
  ret += (size_t)printVK(fp, (char *)"minchildren", str, 1);
  if (node->info->has_maxChildrenNumber) {
    snprintf(str, 4, "%zu", node->info->maxChildrenNumber);
    ret += (size_t)printVK(fp, (char *)"maxchildren", str, 1);
  }
  snprintf(str, 4, "%zu", node->info->minFathersNumber);
  ret += (size_t)printVK(fp, (char *)"minfathers", str, 1);
  if (node->info->has_maxFathersNumber) {
    snprintf(str, 4, "%zu", node->info->maxFathersNumber);
    ret += (size_t)printVK(fp, (char *)"maxfathers", str, 1);
  }
  free(str);

  ret += (size_t)printVK(fp, (char *)"opcode", (char*) node->info->opcode.c_str(), 1);
  ret += (size_t)printVKint(fp, (char *)"nargs", (int) node->info->nargs, 1);
  
  if (node->info->nargs >= 1){
    ret += (size_t)printVK(fp, (char *)"arg1", (char*) node->info->arg1.c_str(), 1);
  }
  
  if (node->info->nargs >= 2){
    ret += (size_t)printVK(fp, (char *)"arg2", (char*) node->info->arg2.c_str(), 1);
  }
  
  if (node->info->nargs >= 3){
    ret += (size_t)printVK(fp, (char *)"arg3", (char*) node->info->arg3.c_str(), 1);
  }
  
  if (node == root)
    ret += (size_t)fprintf(fp, ", style=\"bold,filled\", fillcolor=yellow]\n");
  else
    ret += (size_t)fprintf(fp, "]\n");

  return ret;
}

size_t node_edges_to_dot(const node_t *node, FILE *fp)
{
  size_t ret;

  ret = 0;  
  if (node->has_child1){
      if (sizeof(vsize_t) >= 8){
        ret += (size_t)fprintf(fp, "\"%" PRIx64 "\" -> \"%" PRIx64 "\" [label=1, childnumber=1]", node->node_id, node->child1->node_id);
      }
      else {
        // Typically: vsize_t on a 32 bits machine
        ret += (size_t)fprintf(fp, "\"%x\" -> \"%x\" [label=1, childnumber=1]", (unsigned int) node->node_id, (unsigned int) node->child1->node_id);
      }
  ret += (size_t)fprintf(fp, "\n");
  }
  
  if (node->has_child2){
    if (sizeof(vsize_t) >= 8){
      ret += (size_t)fprintf(fp, "\"%" PRIx64 "\" -> \"%" PRIx64 "\" [label=2, childnumber=2]", node->node_id, node->child2->node_id);
    }
    else {
      // Typically: vsize_t on a 32 bits machine
      ret += (size_t)fprintf(fp, "\"%x\" -> \"%x\" [label=2, childnumber=2]", (unsigned int) node->node_id, (unsigned int) node->child2->node_id);
    }

    ret += (size_t)fprintf(fp, "\n");
  }
  
  return ret;
}
