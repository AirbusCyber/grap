# sources
set(SRCS_TESTS
  tests.cpp
  tests.hpp
  )

# tests
add_executable(tests ${SRCS_TESTS})
configure_file(test_all.py ${CMAKE_BINARY_DIR}/test_all.py COPYONLY)

if("${MSVC}" OR "${MSYS}")
  target_link_libraries(tests common GTSI graph nodeinfo)
else()
  target_link_libraries(tests seccomp common GTSI graph nodeinfo)
endif()  

add_custom_target(test COMMAND python2 ${CMAKE_BINARY_DIR}/test_all.py WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
