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

char *csymbtypeToString(enum label_t cst) {
  char *rs;
  switch (cst) {
  case LABEL_STAR:
    rs = "*";
    break;
  case LABEL_GENERIC_OPCODE:
    rs = "gopcode";
    break;
  case LABEL_EXACT_OPCODE:
    rs = "opcode";
    break;
  case LABEL_SUBSTRING:
    rs = "substring";
    break;
  case LABEL_EXACT_STRING:
    rs = "string";
    break;
  case LABEL_REGEX:
    rs = "regex";
    break;
  default:
    rs = "string";
  }

  char *s = (char *) malloc((strlen(rs) + 1) * sizeof(char));
  memcpy(s, rs, (strlen(rs) + 1) * sizeof(char));
  s[strlen(s)] = 0;
  return s;
}

char *symbToString(vsize_t symb) {
  char *rs;
  switch (symb) {
  case INST_SEQ:
    rs = "INST";
    break;
  case INST_RET:
    rs = "RET";
    break;
  case INST_CALL:
    rs = "CALL";
    break;
  case INST_JCC:
    rs = "JCC";
    break;
  case INST_JMP:
    rs = "JUMP";
    break;
  case INST_END:
    rs = "HLT";
    break;
  case INST_UREACH:
    rs = "UNREACHEABLE";
    break;
  case INST_UNDEF:
    rs = "UNDEFINED";
    break;
  case INST_SCALL:
    rs = "INT";
    break;
  default:
  case SYMB_END:
    rs = "ERROR";
    break;
  }

  char *s = (char *) malloc((strlen(rs) + 1) * sizeof(char));
  memcpy(s, rs, strlen(rs) * sizeof(char));
  s[strlen(rs)] = 0;
  return s;
}

// char *repeatTypeToString(enum repeat_t rt) {
//   char *rs;
//   switch (rt) {
//   case REPEAT_SINGLE:
//     rs = ".";
//     break;
//   case REPEAT_PLUS:
//     rs = "+";
//     break;
//   case REPEAT_STAR:
//     rs = "*";
//     break;
//   default:
//     rs = ".";
//   }
// 
//   char *s = (char *) malloc((strlen(rs) + 1) * sizeof(char));
//   memcpy(s, rs, (strlen(rs) + 1) * sizeof(char));
//   s[strlen(s)] = 0;
//   return s;
// }

size_t node_to_dot(const node_t * node, const node_t * root, size_t node_number, FILE * fp) {
  size_t ret;

  ret = fprintf(fp, "\"%" PRIx64 "\" [", node->node_id);
  char *s = symbToString(node->symb);

  ret += fprintf(fp, "symb = ");
  ret += fprintf(fp, "%s", s);


  if (node->version != 2) {
    fprintf(fp, ", label = \"%" PRIx64 "(%d) : ", node->node_id, (int) node_number);
    ret += fprintf(fp, "%s", s);
    ret += fprintf(fp, "%s", "\"");
  }
  else {
    //printing label
    fprintf(fp, ", label = \"%" PRIx64 "(%d) : ", node->node_id, (int) node_number);
    char *ss;
    ret += fprintf(fp, "%s", "(");
    ret += fprintf(fp, "%s", node->csymb);
    ret += fprintf(fp, "%s", ")");

    if (node->minRepeat > 1 || !node->hasMaxRepeat || node->maxRepeat > 1) {
      ret += fprintf(fp, "{%d,", node->minRepeat);

      if (node->hasMaxRepeat) {
        ret += fprintf(fp, "%d}", node->maxRepeat);
      }
      else {
        ret += fprintf(fp, "}");
      }
    }

    if (node->minChildrenNumber > 0) {
      ret += fprintf(fp, "(c>=%d)", node->minChildrenNumber);
    }
    if (node->hasMaxChildrenNumber) {
      ret += fprintf(fp, "(c<=%d)", node->maxChildrenNumber);
    }
    if (node->minFathersNumber > 0) {
      ret += fprintf(fp, "(f>=%d)", node->minFathersNumber);
    }
    if (node->hasMaxFathersNumber) {
      ret += fprintf(fp, "(f<=%d)", node->maxFathersNumber);
    }
    ret += fprintf(fp, "%s", "\"");

    //printing other props
    ss = csymbtypeToString(node->csymbType);
    ret += printVK(fp, "csymbtype", ss, 1);
    ret += printVK(fp, "csymb", node->csymb, 1);
    if (node->minRepeat != 1)
      ret += printVKint(fp, "minrepeat", node->minRepeat, 1);
    if (node->hasMaxRepeat == 1)
      ret += printVKint(fp, "maxnrepeat", node->maxRepeat, 1);
    free(ss);
    char *str = malloc(4 * sizeof(char));
    snprintf(str, 4, "%d", node->minChildrenNumber);
    ret += printVK(fp, "minchildren", str, 1);
    if (node->hasMaxChildrenNumber) {
      snprintf(str, 4, "%d", node->maxChildrenNumber);
      ret += printVK(fp, "maxchildren", str, 1);
    }
    snprintf(str, 4, "%d", node->minFathersNumber);
    ret += printVK(fp, "minfathers", str, 1);
    if (node->hasMaxFathersNumber) {
      snprintf(str, 4, "%d", node->maxFathersNumber);
      ret += printVK(fp, "maxfathers", str, 1);
    }
    free(str);
  }
  free(s);

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

size_t node_to_file(const node_t * node, FILE * fp) {
  size_t ret, count;

  ret = 0;

  count = fwrite_le_swap(&node->node_id, sizeof(node->node_id), 1, fp);
  ret += count * sizeof(node->node_id);

  count = fwrite_le_swap(&node->symb, sizeof(node->symb), 1, fp);
  ret += count * sizeof(node->symb);

  return ret;
}

size_t node_edges_to_file(const node_t * node, FILE * fp) {
  vsize_t j;
  size_t ret;

  ret = 0;
  for (j = 0; j < node->children_nb; ++j) {
    const node_t *child;

    child = node_child_const(node, j);

    putc('e', fp);
    ret++;

    ret += fwrite_le_swap(&node->node_id, sizeof(node->node_id), 1, fp) * sizeof(node->node_id);
    ret += fwrite_le_swap(&child->node_id, sizeof(child->node_id), 1, fp) * sizeof(child->node_id);
  }
  return ret;
}

size_t node_from_file(node_t * node, FILE * fp) {
  size_t ret;

  ret = 0;
  ret += fread_le_swap(&node->node_id, sizeof(node->node_id), 1, fp) * sizeof(node->node_id);
  ret += fread_le_swap(&node->symb, sizeof(node->symb), 1, fp) * sizeof(node->symb);

  return ret;
}
