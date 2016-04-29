#include "graphParser.hpp"

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

graph_t *getGraphFromFile (FILE * f) {
  graph_t *graph;
  yyscan_t scanner;
  YY_BUFFER_STATE state;

  fseek (f, 0, SEEK_END);
  size_t fsize = (size_t) ftell (f);
  fseek (f, 0, SEEK_SET);
  
  char *buf = (char *) malloc (fsize + 1);
  size_t  read = fread (buf, 1, fsize, f);
  RELEASE_ASSERT(read == fsize);
  
  buf[fsize] = 0;

  if (yylex_init (&scanner)) {
    // couldn't initialize
    std::cout << "ERR: couldn't initialize yylex." << std::endl;
    return NULL;
  }

  state = yy_scan_string (buf, scanner);
  if (yyparse (&graph, scanner)) {
    // error parsing
    std::cout << "ERR: parsing failed." << std::endl;
    return NULL;
  }

  yy_delete_buffer (state, scanner);
  free (buf);
  yylex_destroy (scanner);

  return graph;
}

graph_t *getGraphFromPath (const char *path) {
  FILE *f = fopen (path, "rb");
  if (f != NULL) { 
    graph_t* g = getGraphFromFile (f);
    fclose(f);
    return g;
  }
  else return NULL; 
}
