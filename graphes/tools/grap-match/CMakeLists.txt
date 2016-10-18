# sources
set(SRCS_GRAP-MATCH
  grap-match.cpp
  grap-match.hpp
  )

# grap-match
add_executable(grap-match ${SRCS_GRAP-MATCH})
target_link_libraries(grap-match common GTSI graph nodeinfo pthread)

if(NOT "${MSVC}" AND NOT "${MSYS}")
  install (TARGETS grap-match DESTINATION /usr/local/bin) 
endif()
