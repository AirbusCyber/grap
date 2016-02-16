cmake_minimum_required(VERSION 2.6)
project(grap)
CMAKE_POLICY(SET CMP0015 NEW)
set(CMAKE_CXX_FLAGS " -std=c++11")

set(CMAKE_CXX_FLAGS_VALGRIND "-g")
set(CMAKE_C_FLAGS_VALGRIND "-g")

set(CMAKE_CXX_FLAGS_DEBUG " -g -fsanitize=address")
set(CMAKE_C_FLAGS_DEBUG " -g -fsanitize=address")

# No optimization on "Release" (it induces bugs in the parser)
set(CMAKE_CXX_FLAGS_RELEASE "")
set(CMAKE_C_FLAGS_RELEASE "")

include_directories(
	./
	src/
	libs/include/
	libs/libgraph/
	libsGTSI/
	libsGTSI/Traversal/
	libs/dict/
	libs/dotparser/
        libs/node_info/
)

#shared libs
#add_library(dict 
#      libs/dict/dict.c
#      libs/dict/dict.h
#)

# Dot parser
# Create target for the parser
ADD_CUSTOM_TARGET(simpledotparser echo "Creating dotparser")

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

#add_library(parser Parser.c Lexer.c)
#add_library(libsimpledotparser 
#			libs/dotparser/graphParser.c 
#			Lexer.c 
#			Parser.c 
#			libs/dotparser/Expression.c
#)
add_library(graph
      libs/libgraph/graph.h
      libs/libgraph/graph.c
      libs/libgraph/graphIO.h
      libs/libgraph/graphIO.c
      libs/libgraph/node.h
      libs/libgraph/node.c
      libs/libgraph/node_list.h
      libs/libgraph/node_list.c
      libs/libgraph/nodeIO.h
      libs/libgraph/nodeIO.c
      libs/dict/dict.c
      libs/dict/dict.h
      libs/dotparser/graphParser.c 
	  Lexer.c 
	  Parser.c 
	  libs/dotparser/Expression.c
)
#add_executable(sdp libs/dotparser/main.c)

#add_executable(sdp libs/dotparser/main.c libs/dotparser/graphParser.c Lexer.c Parser.c libs/dotparser/Expression.c)
#target_link_libraries(graph libsimpledotparser)
#target_link_libraries(sdp graph)

# Node Info
add_library(nodeinfo libs/node_info/node_info.cpp)

# GTSI
add_library(libGTSI libGTSI.cpp
      libsGTSI/utils-gtsi.cpp
      libsGTSI/Traversal/Traversal.cpp
)

# grap (GTSI)
add_executable(GTSI-grap GTSI-grap.cpp)
target_link_libraries(GTSI-grap libGTSI graph)

# tests
add_executable(tests tests.cpp)
target_link_libraries(tests libGTSI graph pthread nodeinfo)

# todot
add_executable(todot todot.cpp)
target_link_libraries(todot graph)
