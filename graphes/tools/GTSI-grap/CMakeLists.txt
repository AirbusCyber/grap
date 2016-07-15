# sources
set(SRCS_GTSIGRAP
  GTSI-grap.cpp
  GTSI-grap.hpp
  )

# grap (GTSI-grap)
add_executable(GTSI-grap ${SRCS_GTSIGRAP})
target_link_libraries(GTSI-grap common GTSI graph nodeinfo)
install (TARGETS GTSI-grap DESTINATION /usr/local/bin) 
