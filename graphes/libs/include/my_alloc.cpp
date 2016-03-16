#include "my_alloc.hpp"

void* malloc_or_quit(size_t s){
    void *v = malloc(s);
    RELEASE_ASSERT(v != 0);
    return v;
}

void* calloc_or_quit(size_t n, size_t s){
    void *v = calloc(n, s);
    RELEASE_ASSERT(v != 0);
    return v;
}

void* realloc_or_quit(void* p, size_t s){
    void *v = realloc(p, s);
    RELEASE_ASSERT(s == 0 or v != 0);
    return v;
}