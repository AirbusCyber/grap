# sources
set(SRCS_GRAPH
  graph.cpp
  graph.hpp
  graphIO.cpp
  graphIO.hpp
  node.cpp
  node.hpp
  node_list.cpp
  node_list.hpp
  nodeIO.cpp
  nodeIO.hpp
  )

# graph object-library
add_library(graph-obj OBJECT ${SRCS_GRAPH})

# Bindings
list_combinations(SRCS_GRAPH_BINDING
  PREFIXES ${CMAKE_CURRENT_SOURCE_DIR}/
  SUFFIXES ${SRCS_GRAPH})
binding_add_srcs("${SRCS_GRAPH_BINDING}")
