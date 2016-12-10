#include "todot.hpp"

int main(int argc, char* argv[]){
  if (argc <= 2){
    std::cout << "Usage: ./todot (in.dot) (out.dot)\n";
  }

  std::cerr << "WARNING: ./todot is deprecated, conditions are not exported." << std::endl;
  
  char* pathIn = argv[1];
  char* pathOut = argv[2];

  graph_t* gr;

  FILE* fpIn;
  FILE* fpOut;

  fpIn = fopen(pathIn, "r");
  fpOut = fopen(pathOut, "w");

  if (fpIn == NULL || fpOut == NULL){
    return 1;
  }

  gr = getGraphFromFile(fpIn);
  fclose(fpIn);

  if (gr != NULL){
    graph_fprint(fpOut, gr);
  }
  fclose(fpOut);
}