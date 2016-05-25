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
