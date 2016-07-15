# Change the location of executables
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})
set (TOOLS OFF CACHE BOOL "Tools")

if(${TOOLS})

  # grap-match
  add_subdirectory(grap-match)

  # grap
  add_subdirectory(grap)

  # tests
  add_subdirectory(tests)

  # todot
  add_subdirectory(todot)

endif(${TOOLS})
