#ifndef SYMBOL_H
#define SYMBOL_H

#include "ga_types.h"
/*!
 @file symbol.h
 @brief Define the node symbols used during extraction and automata.
 */

/*!
 @brief The node symbol, corresponding to the king of instruction
 or a path pointer when the graph is converted in a tree
 */
enum {
  /*!
   @brief Initial symbol.
   */
  SYMB_INIT = 0,

  /*!
   @brief Procedure return.
   */
  INST_RET, //1

  /*!
   @brief Procedure call.
   */
  INST_CALL, //2

  /*!
   @brief Unconditional jump.
   */
  INST_JMP, //3

  /*!
   @brief End instruction.
   */
  INST_END, //4

  /*!
   @brief System call.
   */
  INST_SCALL, //5

  /*!
   @brief Unreachable instruction.
   */
  INST_UREACH, //6

  /*!
   @brief Undefined instruction.
   */
  INST_UNDEF, //7

  /*!
   @brief Conditional jump.
   */
  INST_JCC, //8

  /*!
   @brief Sequential instruction.
   */
  INST_SEQ, //9

  /*!
   @brief Path symbol. (For graph to tree transformation)
   */
  SYMB_PATH, //10

  /*! 
   @brief Last symbol;
   */
  SYMB_END //11
};

/*!
 @brief Symbol enum is mapped on a uint32_t.

 Using directly enums is always a bad idea for code portability. The use of
 uint32_t allows compliance with C++.
 */
typedef uint32_t symb_t;

#endif
