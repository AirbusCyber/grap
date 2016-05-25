# Change the location of executables
set (CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR})

# grap (GTSI-grap)
add_subdirectory(GTSI-grap)

# tests
add_subdirectory(tests)

# todot
add_subdirectory(todot)

