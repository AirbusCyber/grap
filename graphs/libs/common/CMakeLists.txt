# sources
set(SRCS_COMMON
  my_alloc.cpp
  ga_types.hpp
  my_alloc.hpp
  my_assert.hpp
  )

# common object-library
add_library(common-obj OBJECT ${SRCS_COMMON})

# common types and functions (alloc_or_quit for instance)
add_library(common $<TARGET_OBJECTS:common-obj>)

# Bindings
list_combinations(SRCS_COMMON_BINDING
  PREFIXES ${CMAKE_CURRENT_SOURCE_DIR}/
  SUFFIXES ${SRCS_COMMON})
binding_add_srcs("${SRCS_COMMON_BINDING}")
