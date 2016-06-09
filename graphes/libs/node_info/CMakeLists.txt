# sources
set(SRCS_NODEINFO
  node_info.cpp
  node_info.hpp
  )

# nodeinfo library
add_library(nodeinfo ${SRCS_NODEINFO})

# Bindings
list_combinations(SRCS_NODEINFO_BINDING
  PREFIXES ${CMAKE_CURRENT_SOURCE_DIR}/
  SUFFIXES ${SRCS_NODEINFO})
binding_add_srcs("${SRCS_NODEINFO_BINDING}")
