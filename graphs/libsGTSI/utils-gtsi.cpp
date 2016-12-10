#ifndef UTILS_CPP
#define UTILS_CPP

#include "utils-gtsi.hpp"
#include <ios>


string b2s(bool b){
  return b ? "true" : "false";
}

string h2s(uint64_t a){
  string str;
  char* buff = (char*) calloc_or_quit(16, sizeof(char));
  sprintf(buff, "%lx", (long int) a);
  str += buff;
  free(buff);
  return str;
}

#endif
