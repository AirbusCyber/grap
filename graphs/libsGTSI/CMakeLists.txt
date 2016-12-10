SET(SRCS_LIBGTSI
  utils-gtsi.cpp
  utils-gtsi.hpp
  )

# Traversal directory
add_subdirectory(Traversal)

# utils-GTSI object-library
add_library(utils-GTSI OBJECT ${SRCS_LIBGTSI})

# libGTSI library
add_library(GTSI
  $<TARGET_OBJECTS:utils-GTSI>
  $<TARGET_OBJECTS:Traversal>
)

# Bindings
list_combinations(SRCS_LIBGTSI_BINDING
  PREFIXES ${CMAKE_CURRENT_SOURCE_DIR}/
  SUFFIXES ${SRCS_LIBGTSI})
binding_add_srcs("${SRCS_LIBGTSI_BINDING}")
