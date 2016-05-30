cmake_minimum_required(VERSION 2.8)
project(grap)
CMAKE_POLICY(SET CMP0015 NEW)

if(${MSVC})
  # Don't include uinstd.h in Lexer.h
  add_definitions(-DYY_NO_UNISTD_H)
  
  # Increase stack size
  set(CMAKE_EXE_LINKER_FLAGS "/STACK:1000000000")
else()
  # Less warnings in C in order to avoid warnings about flex/bison code
  set(CMAKE_CXX_FLAGS " -std=c++11 -pedantic -Wall -Wno-write-strings -Wextra -Wcast-align -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Woverloaded-virtual -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Wno-unused")

  set(CMAKE_CXX_FLAGS_VALGRIND " -g")
  set(CMAKE_C_FLAGS_VALGRIND " -g")

  set(CMAKE_CXX_FLAGS_DEBUG " -g -fsanitize=address")
  set(CMAKE_C_FLAGS_DEBUG " -g -fsanitize=address")

  set(CMAKE_CXX_FLAGS_ERRALL " -g -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs
  -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused")

  set(CMAKE_C_FLAGS_ERRALL " -g -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept
  -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Werror -Wno-unused")

endif()

include_directories(
  ./
  libs/common/
  libs/libgraph/
  libs/dotparser/
  libsGTSI/
  libsGTSI/Traversal/
  libs/node_info/
  ${CMAKE_BINARY_DIR}/libs/dotparser/
)

# Libraries-----------------------------------------------------------------
# Libs
add_subdirectory(libs)

# GTSI
add_subdirectory(libsGTSI)

# Executables---------------------------------------------------------------
add_subdirectory(tools)
