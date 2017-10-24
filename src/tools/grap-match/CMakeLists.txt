# sources
set(SRCS_GRAP-MATCH
  grap-match.cpp
  grap-match.hpp
  )

add_executable(grap-match ${SRCS_GRAP-MATCH})

if("${MSVC}" OR "${MSYS}")
  target_link_libraries(grap-match common GTSI graph nodeinfo)
else()
  target_link_libraries(grap-match seccomp common GTSI graph nodeinfo pthread)
  target_link_libraries(grap-match ${Boost_SYSTEM_LIBRARY} ${Boost_FILESYSTEM_LIBRARY})
endif()  
configure_file(grap-match.py ${CMAKE_BINARY_DIR}/grap-match.py COPYONLY)

if(NOT "${MSVC}" AND NOT "${MSYS}")
  install (TARGETS grap-match DESTINATION /usr/local/bin) 
endif()
