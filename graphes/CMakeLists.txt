cmake_minimum_required(VERSION 2.6)
project(grap)
CMAKE_POLICY(SET CMP0015 NEW)

if(${MSVC})
  # Don't include uinstd.h in Lexer.h
  add_definitions(-DYY_NO_UNISTD_H)
  
  # Increase stack size
  set(CMAKE_EXE_LINKER_FLAGS "/STACK:1000000000")
else()
  set(CMAKE_CXX_FLAGS " -std=c++11 -pedantic -Wall -Wno-write-strings -Wextra -Wcast-align -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Woverloaded-virtual -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Wno-unused")

  # Less warnings in C in order to avoid warnings about flex/bison code
  set(CMAKE_C_FLAGS " -std=c++11 -pedantic -Wall -Wno-write-strings -Wno-return-type -Wextra -Wcast-align -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wnoexcept -Woverloaded-virtual -Wshadow -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wundef -Wno-unused")

  set(CMAKE_CXX_FLAGS_VALGRIND " -g")
  set(CMAKE_C_FLAGS_VALGRIND " -g")

  set(CMAKE_CXX_FLAGS_DEBUG " -g -fsanitize=address")
  set(CMAKE_C_FLAGS_DEBUG " -g -fsanitize=address")

  set(CMAKE_CXX_FLAGS_ERRALL " -g -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused")
  set(CMAKE_C_FLAGS_ERRALL " -g -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused")
endif()


include_directories(
  ./
  libs/include/
  libs/libgraph/
  libs/dotparser/
  libsGTSI/
  libsGTSI/Traversal/
  libs/node_info/
  ${CMAKE_BINARY_DIR}
)

# Dot parser
# Create custom command for flex/lex
if(${MSVC})
  if (EXISTS Lexer.cpp AND EXISTS Lexer.h AND EXISTS Parser.cpp AND EXISTS Parser.h)
    message("Found Lexer.cpp, Lexer.h, Parser.cpp and Parser.h.")
  else()
    message("Lexer.cpp, Lexer.h, Parser.cpp or Parser.h not found: generate them with flex / bison (with make on Linux) then put them in the current directory.")
  endif()
else()
  ADD_CUSTOM_COMMAND(
    OUTPUT Lexer.c
    OUTPUT Lexer.h
    COMMAND flex
    ARGS    ${CMAKE_SOURCE_DIR}/libs/dotparser/Lexer.l
    DEPENDS  ${CMAKE_SOURCE_DIR}/libs/dotparser/Lexer.l
  )

  # Copy Lexer.c to Lexer.cpp (so it will be compiled as a C++ file)
  ADD_CUSTOM_COMMAND(
    OUTPUT Lexer.cpp
    COMMAND cp
    ARGS    Lexer.c Lexer.cpp
    DEPENDS  Lexer.c
  )

  # Create custom command for bison/yacc
  ADD_CUSTOM_COMMAND(
    OUTPUT Parser.c
    OUTPUT Parser.h
    COMMAND bison
    ARGS -y ${CMAKE_SOURCE_DIR}/libs/dotparser/Parser.y
    DEPENDS ${CMAKE_SOURCE_DIR}/libs/dotparser/Parser.y
  )

  # Copy Parser.c to Parser.cpp (so it will be compiled as a C++ file)
  ADD_CUSTOM_COMMAND(
    OUTPUT Parser.cpp
    COMMAND cp
    ARGS    Parser.c Parser.cpp
    DEPENDS  Parser.c
  )
endif()


# Common types and functions (alloc_or_quit for instance)
add_library(common libs/include/my_alloc.cpp)

# libgraph
add_library(graph
  libs/include/my_alloc.cpp
  libs/libgraph/graph.hpp
  libs/libgraph/graph.cpp
  libs/libgraph/graphIO.hpp
  libs/libgraph/graphIO.cpp
  libs/libgraph/node.hpp
  libs/libgraph/node.cpp
  libs/libgraph/node_list.hpp
  libs/libgraph/node_list.cpp
  libs/libgraph/nodeIO.hpp
  libs/libgraph/nodeIO.cpp
  libs/dotparser/graphParser.cpp
  libs/dotparser/Expression.cpp
  Parser.cpp
  Lexer.cpp
)

# Node Info
add_library(nodeinfo libs/node_info/node_info.cpp)

# GTSI
add_library(libGTSI
  libsGTSI/utils-gtsi.cpp
  libsGTSI/Traversal/Traversal.cpp
)

# grap (GTSI-grap)
add_executable(GTSI-grap GTSI-grap.cpp)
target_link_libraries(GTSI-grap common libGTSI graph nodeinfo)

# tests
add_executable(tests tests.cpp)
if(${MSVC})
  target_link_libraries(tests common libGTSI graph nodeinfo)
else()
  target_link_libraries(tests seccomp common libGTSI graph nodeinfo)
endif()

# todot
add_executable(todot todot.cpp)
target_link_libraries(todot common graph nodeinfo)
