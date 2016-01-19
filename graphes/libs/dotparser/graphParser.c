#include "graphParser.h"

graph_t *getGraph (const char *expr) {
  graph_t *graph;
  yyscan_t scanner;
  YY_BUFFER_STATE state;

  if (yylex_init (&scanner)) {
    // couldn't initialize
    return NULL;
  }

  state = yy_scan_string (expr, scanner);

  if (yyparse (&graph, scanner)) {
    // error parsing
    return NULL;
  }

  yy_delete_buffer (state, scanner);

  yylex_destroy (scanner);

  return graph;
}

int test43 (int b) {
  return 3;
}

graph_t *getGraphFromFile (FILE * f) {
  graph_t *graph;
  yyscan_t scanner;
  YY_BUFFER_STATE state;

  fseek (f, 0, SEEK_END);
  long fsize = ftell (f);
  fseek (f, 0, SEEK_SET);

  char magic[GRAPHBINMAGIC_LEN];

  /* Check Magic value */
  fread_le_swap (magic, 1, GRAPHBINMAGIC_LEN, f);
  if (strncmp (magic, GRAPHBINMAGIC, GRAPHBINMAGIC_LEN) == 0) {
    graph_from_file (&graph, f);
    return graph;
  }

  fseek (f, 0, SEEK_SET);
  char *buf = (char *) malloc (fsize + 1);
  fread (buf, fsize, 1, f);

  buf[fsize] = 0;


  if (yylex_init (&scanner)) {
    // couldn't initialize
    return NULL;
  }

  state = yy_scan_string (buf, scanner);
  if (yyparse (&graph, scanner)) {
    // error parsing
    return NULL;
  }

  yy_delete_buffer (state, scanner);

  free (buf);

  yylex_destroy (scanner);

  return graph;
}

graph_t *getGraphFromPath (const char *path) {
  FILE *f = fopen (path, "rb");
  return getGraphFromFile (f);
}
