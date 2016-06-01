# Variables-----------------------------------------------------------------
set(PYTHON_BINDING OFF CACHE BOOL "Python bindings")

if(PYTHON_BINDING)  

  # Variables
  set(SWIG_FILE pygrap.i)
  get_property(SRCS GLOBAL PROPERTY SRCS_BINDING)

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

      SWIG_ADD_MODULE(pygrap python ${SWIG_FILE} ${SRCS})

      # Removed warnings for the binding
      SET_SOURCE_FILES_PROPERTIES(${SRCS} PROPERTIES COMPILE_FLAGS "-w")
      SET_SOURCE_FILES_PROPERTIES(${swig_generated_file_fullname} PROPERTIES
	COMPILE_FLAGS "-w"
	GENERATED TRUE)
      
      SWIG_LINK_LIBRARIES(pygrap ${PYTHON_LIBRARIES})
      
    endif(PYTHONLIBS_FOUND)
  endif(SWIG_FOUND)
  
endif(PYTHON_BINDING)
