# Variables-----------------------------------------------------------------
set(SWIG_FILE libgraph.i)
get_property(SRCS GLOBAL PROPERTY SRCS_BINDING)

# message("${SRCS}")

# SWIG
FIND_PACKAGE(SWIG REQUIRED)

if(SWIG_FOUND)
  INCLUDE(${SWIG_USE_FILE})

  # Python
  FIND_PACKAGE(PythonLibs)

  if(PYTHONLIBS_FOUND)

    # Includes
    INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH})
    INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
    
    SET_SOURCE_FILES_PROPERTIES(${SWIG_FILE} PROPERTIES CPLUSPLUS ON)
    SET_SOURCE_FILES_PROPERTIES(${SWIG_FILE} PROPERTIES SWIG_FLAGS "-builtin")
    # Forcing the generation of the parser and lexer
    SET_SOURCE_FILES_PROPERTIES(${SRCS} PROPERTIES GENERATED TRUE)
    
    SWIG_ADD_MODULE(libgraph python ${SWIG_FILE} ${SRCS})
        
    SWIG_LINK_LIBRARIES(libgraph ${PYTHON_LIBRARIES})
    
  endif(PYTHONLIBS_FOUND)
endif(SWIG_FOUND)
