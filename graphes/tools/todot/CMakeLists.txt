# sources
set(SRCS_TODOT
  todot.cpp
  todot.hpp
  )

# todot
add_executable(todot ${SRCS_TODOT})
target_link_libraries(todot common graph nodeinfo)
