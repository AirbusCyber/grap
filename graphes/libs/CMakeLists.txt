# dotparser
add_subdirectory(dotparser)

# node_info
add_subdirectory(node_info)

# common
add_subdirectory(common)

# graph
add_subdirectory(libgraph)


# libgraph
add_library(graph
  $<TARGET_OBJECTS:dotparser-obj>
  $<TARGET_OBJECTS:common-obj>
  $<TARGET_OBJECTS:graph-obj>
  ${BISON_Parser_OUTPUTS}
  ${FLEX_Scanner_OUTPUTS}
  )
