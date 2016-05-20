cmake_minimum_required(VERSION 2.6)
project(grap)
CMAKE_POLICY(SET CMP0015 NEW)

set(CMAKE_CXX_FLAGS " -std=c++11 -pedantic -Wall -Wno-write-strings -Wextra -Wcast-align -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Woverloaded-virtual -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Wno-unused")

# Less warnings in C in order to avoid warnings about flex/bison code
set(CMAKE_C_FLAGS " -std=c++11 -pedantic -Wall -Wno-write-strings -Wno-return-type -Wextra -Wcast-align -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-include-dirs -Wnoexcept -Woverloaded-virtual -Wshadow -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wundef -Wno-unused")

set(CMAKE_CXX_FLAGS_VALGRIND " -g")
set(CMAKE_C_FLAGS_VALGRIND " -g")

set(CMAKE_CXX_FLAGS_DEBUG " -g -fsanitize=address")
set(CMAKE_C_FLAGS_DEBUG " -g -fsanitize=address")

set(CMAKE_CXX_FLAGS_ERRALL " -g -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused")
set(CMAKE_C_FLAGS_ERRALL " -g -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused")

# Default option for release is -O3
#set(CMAKE_CXX_FLAGS_RELEASE "")
#set(CMAKE_C_FLAGS_RELEASE "")

# Force C++
SET(CMAKE_C_COMPILER ${CMAKE_CXX_COMPILER})


include_directories(
  ./
  libs/include/
  libs/libgraph/
  libsGTSI/
  libsGTSI/Traversal/
  libs/dict/
  libs/dotparser/
  libs/node_info/
)

add_library(common libs/include/my_alloc.cpp)

#shared libs
#add_library(dict 
#      libs/dict/dict.c
#      libs/dict/dict.h
#)

# Dot parser
# Create target for the parser
#ADD_CUSTOM_TARGET(simpledotparser echo "Creating dotparser")

# Create custom command for flex/lex (note the outputs)
ADD_CUSTOM_COMMAND(
  OUTPUT Lexer.c
  COMMAND flex
  ARGS    libs/dotparser/Lexer.l
  DEPENDS  libs/dotparser/Lexer.l
)

# Create custom command for bison/yacc (note the DEPENDS)
ADD_CUSTOM_COMMAND(
  OUTPUT Parser.c
  COMMAND bison
  ARGS -y libs/dotparser/Parser.y
  DEPENDS Lexer.c
  DEPENDS libs/dotparser/Parser.y
)

# Add parser.c to the list of sources
# SET(Foo_SRCS ${Foo_SRCS} Parser.c)

#add_library(libsimpledotparser 
#			libs/dotparser/graphParser.c 
#			Lexer.c 
#			Parser.c 
#			libs/dotparser/Expression.c
#)
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
  libs/dict/dict.cpp
  libs/dict/dict.hpp
  libs/dotparser/graphParser.cpp
  libs/dotparser/Expression.cpp
  Parser.c
  Lexer.c
)


#add_executable(sdp libs/dotparser/main.c)

#add_executable(sdp libs/dotparser/main.c libs/dotparser/graphParser.c Lexer.c Parser.c libs/dotparser/Expression.c)
#target_link_libraries(graph libsimpledotparser)
#target_link_libraries(sdp graph)

# Node Info
add_library(nodeinfo libs/node_info/node_info.cpp)

# GTSI
add_library(libGTSI
  libsGTSI/utils-gtsi.cpp
  libsGTSI/Traversal/Traversal.cpp
)

# grap (GTSI)
add_executable(GTSI-grap GTSI-grap.cpp)
target_link_libraries(GTSI-grap common libGTSI graph nodeinfo)

# tests
add_executable(tests tests.cpp)
target_link_libraries(tests seccomp common libGTSI graph nodeinfo)

# todot
add_executable(todot todot.cpp)
target_link_libraries(todot common graph nodeinfo)
