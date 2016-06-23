# sources
set(SRCS_TESTS
  tests.cpp
  tests.hpp
  )

# tests
add_executable(tests ${SRCS_TESTS})

if("${MSVC}" OR "${MSYS}")
  target_link_libraries(tests common GTSI graph nodeinfo boost_regex)
else()
  target_link_libraries(tests seccomp common GTSI graph nodeinfo boost_regex)
endif()
