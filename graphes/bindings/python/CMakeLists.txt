# Variables-----------------------------------------------------------------
set(PYTHON_BINDING OFF CACHE BOOL "Python bindings")

# Removes the use of 'pythonxx_d.lib'
if(${MSVC})
  add_definitions("-DSWIG_PYTHON_INTERPRETER_NO_DEBUG")
endif(${MSVC})

if(PYTHON_BINDING)  

  # Variables
  set(SWIG_FILE pygrap.i)
  get_property(SRCS GLOBAL PROPERTY SRCS_BINDING)

  # SWIG
  FIND_PACKAGE(SWIG REQUIRED)

  if(SWIG_FOUND AND Boost_FOUND)
    INCLUDE(${SWIG_USE_FILE})

    # Python
    FIND_PACKAGE(PythonLibs 2.7 REQUIRED)
    FIND_PACKAGE(PythonInterp 2.7 REQUIRED)
    
    if(PYTHONLIBS_FOUND AND PYTHONINTERP_FOUND)

      # Environement
      EXECUTE_PROCESS(COMMAND ${PYTHON_EXECUTABLE}
	-c "from sys import stdout; from distutils import sysconfig; stdout.write(sysconfig.get_python_lib())"
	OUTPUT_VARIABLE PYTHON_LIB_DIR)
      
      IF (NOT PYTHON_SITE_DIR)
	SET (PYTHON_SITE_DIR ${PYTHON_LIB_DIR})
      ENDIF (NOT PYTHON_SITE_DIR)

      # Print information
      MESSAGE(STATUS "Python executable: ${PYTHON_EXECUTABLE}")
      MESSAGE(STATUS "Python inc dir: ${PYTHON_INCLUDE_PATH}")
      MESSAGE(STATUS "Python lib dir: ${PYTHON_LIB_DIR}")
      MESSAGE(STATUS "Python libraries: ${PYTHON_LIBRARIES}")
      MESSAGE(STATUS "Python site dir: ${PYTHON_SITE_DIR}")

      # Includes
      INCLUDE_DIRECTORIES(${PYTHON_INCLUDE_PATH})
      INCLUDE_DIRECTORIES(${CMAKE_CURRENT_SOURCE_DIR})
      
      SET_SOURCE_FILES_PROPERTIES(${SWIG_FILE} PROPERTIES CPLUSPLUS ON)
      SET_SOURCE_FILES_PROPERTIES(${SWIG_FILE} PROPERTIES SWIG_FLAGS "-builtin")
      # Forcing the generation of the parser and lexer
      SET_SOURCE_FILES_PROPERTIES(${SRCS} PROPERTIES GENERATED TRUE)

      # Generation
      SWIG_ADD_MODULE(pygrap python ${SWIG_FILE} ${SRCS})

      # Removed warnings for the binding
      SET_SOURCE_FILES_PROPERTIES(${SRCS} PROPERTIES COMPILE_FLAGS "-w")
      SET_SOURCE_FILES_PROPERTIES(${swig_generated_file_fullname} PROPERTIES
	COMPILE_FLAGS "-w"
	GENERATED TRUE)
      
      SWIG_LINK_LIBRARIES(pygrap ${PYTHON_LIBRARIES} ${Boost_REGEX_LIBRARY})

      # Install
      install(TARGETS ${SWIG_MODULE_pygrap_REAL_NAME} LIBRARY DESTINATION ${PYTHON_SITE_DIR})
      install(FILES ${CMAKE_CURRENT_BINARY_DIR}/pygrap.py DESTINATION ${PYTHON_SITE_DIR})
      
    endif(PYTHONLIBS_FOUND AND PYTHONINTERP_FOUND)
  endif(SWIG_FOUND AND Boost_FOUND)
  
endif(PYTHON_BINDING)
