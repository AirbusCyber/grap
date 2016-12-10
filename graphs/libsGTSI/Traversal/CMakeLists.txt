SET(SRCS_TRAVERSAL
  Traversal.cpp
  Traversal.hpp
  )

# Traversal object-library
add_library(Traversal OBJECT ${SRCS_TRAVERSAL})

# Bindings
list_combinations(SRCS_TRAVERSAL_BINDING
  PREFIXES ${CMAKE_CURRENT_SOURCE_DIR}/
  SUFFIXES ${SRCS_TRAVERSAL})
binding_add_srcs("${SRCS_TRAVERSAL_BINDING}")
