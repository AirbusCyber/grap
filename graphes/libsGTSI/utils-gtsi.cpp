#ifndef UTILS_CPP
#define UTILS_CPP

#include "utils-gtsi.h"


string b2s(bool b){
  return b ? "true" : "false";
}

string h2s(uint64_t a){
  string str;
  char* buff = (char*) calloc(16, sizeof(char));
  sprintf(buff, "%lx", (long int) a);
  str += buff;
  return str;
}

string i2s(int a){
//   string str;
//   char* buff = (char*) calloc(16, sizeof(char));
//   sprintf(buff, "%ld", (long int) a);
//   str += buff;
  return std::to_string(a);
}

#endif
