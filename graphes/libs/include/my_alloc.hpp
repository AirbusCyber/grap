#ifndef MY_ALLOC_HPP
#define MY_ALLOC_HPP

#include "ga_types.hpp"

void* malloc_or_quit(size_t s);
void* calloc_or_quit(size_t n, size_t s);
void* realloc_or_quit(void* p, size_t s);

#endif