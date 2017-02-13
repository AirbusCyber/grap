#include "graphParser.hpp"

GraphList *getGraphList (const char *expr) {
  GraphList* gl;
  yyscan_t scanner;
  YY_BUFFER_STATE state;

  if (yylex_init (&scanner)) {
    // couldn't initialize
    return NULL;
  }

  state = yy_scan_string (expr, scanner);

  if (yyparse (&gl, scanner)) {
    // error parsing
    return NULL;
  }

  yy_delete_buffer (state, scanner);

  yylex_destroy (scanner);

  return gl;
}

GraphList *getGraphListFromFile (FILE * f) {
  GraphList* gl;
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
    std::cerr << "ERROR: Couldn't initialize yylex." << std::endl;
    return NULL;
  }

  state = yy_scan_string (buf, scanner);
  if (yyparse (&gl, scanner)) {
    // error parsing
    std::cerr << "ERROR: Parsing failed." << std::endl;
    return NULL;
  }

  yy_delete_buffer (state, scanner);
  free (buf);
  yylex_destroy (scanner);

  return gl;
}

GraphList *getGraphListFromPath (const char *path) {
  FILE *f = fopen (path, "rb");
  if (f != NULL) { 
    GraphList* gl = getGraphListFromFile (f);
    fclose(f);
    return gl;
  }
  else return NULL; 
}

graph_t *getGraph (const char *expr) {
  return popfreeFirstGraph(getGraphList(expr));
}

graph_t *getGraphFromFile (FILE * f) {
  return popfreeFirstGraph(getGraphListFromFile(f));
}

graph_t *getGraphFromPath (const char *path) {
  return popfreeFirstGraph(getGraphListFromPath(path));
}

graph_t* popfreeFirstGraph(GraphList* gl){
  graph_t* gr;
  if (gl != NULL and gl->size >= 1){
    gr = gl->graphes[0]; 
  }
  else{
    gr = nullptr; 
  }
  
  if (gl != NULL){
    freeGraphList(gl, false, false); 
  }
  return gr;
}
