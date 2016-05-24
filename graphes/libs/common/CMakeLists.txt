set(SRCS_COMMON
  my_alloc.cpp
  ga_types.hpp
  my_alloc.hpp
  my_assert.hpp
  )

# common types and functions (alloc_or_quit for instance)
add_library(common ${SRCS_COMMON})
