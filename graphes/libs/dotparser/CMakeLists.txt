# Dot parser
# Create custom command for flex/lex
if(${MSVC})
  if (EXISTS Lexer.cpp AND EXISTS Lexer.h AND EXISTS Parser.cpp AND EXISTS Parser.h)
    message("Found Lexer.cpp, Lexer.h, Parser.cpp and Parser.h.")
  else()
    message("Lexer.cpp, Lexer.h, Parser.cpp or Parser.h not found: generate them
    with flex / bison (with make on Linux) then put them in the current
    directory.")
  endif()
else()

  find_package(BISON REQUIRED)
  find_package(FLEX REQUIRED)

    if(FLEX_FOUND)

      # Creation of the Lexer
      FLEX_TARGET(Scanner
	Lexer.l
	${CMAKE_CURRENT_BINARY_DIR}/Lexer.cpp
	COMPILE_FLAGS "--header-file=${CMAKE_CURRENT_BINARY_DIR}/Lexer.h"
	)

      if (BISON_FOUND)

	# Creation of the Parser
	BISON_TARGET(Parser
	  Parser.y
	  ${CMAKE_CURRENT_BINARY_DIR}/Parser.cpp
	  COMPILE_FLAGS "-y --defines=${CMAKE_CURRENT_BINARY_DIR}Parser.h"
	  )

      ADD_FLEX_BISON_DEPENDENCY(Scanner Parser)
    else()
      message("[-] Flex issues")
    endif()
  else()
    message("[-] Bison issues")
  endif()

endif()

# sources
set(SRCS_DOTPARSER
  graphParser.cpp
  graphParser.hpp
  Expression.cpp
  Expression.hpp
  ${FLEX_Scanner_OUTPUTS}
  ${BISON_Parser_OUTPUTS}
  )

# dotparser object-library
add_library(dotparser-obj OBJECT ${SRCS_DOTPARSER} )

