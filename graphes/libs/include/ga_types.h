#ifndef MK_GA_TYPES_H
#define MK_GA_TYPES_H

/*!
 @file ga_types.h
 @brief Define all basic types that will be used in the whole project.
 And custom typed allocator, allowing stronger type checking.
 */

#include <stdint.h>
#include <stdlib.h>

/* Format macros */
#ifdef _MSC_VER
# define PRId3 "I32d"
# define PRId64 "I64d"
# define PRIi32 "I32i"
# define PRIi64 "I64i"
# define PRIu32 "I32u"
# define PRIu64 "I64u"
# define PRIx64 "I64x"
# define PRIuS "Iu"
#else
# include <inttypes.h> /* must define __STDC_FORMAT_MACROS in c99 or c++ */
# if __MINGW32__ /* %z is not defined under mingw32 */
#  define PRIuS PRIuPTR
# else
#  define PRIuS "zu"
# endif
#endif

/*!
 @brief Type for VMA addresses, i.e. address in the inspected program if it
 were loaded in memory. program_dump_goto_* functions will convert it into a
 an address in a valid buffer.
 */
typedef uint64_t add_t;

/*!
 @brief Maximum value of add_t.
 */
#define ADDR_MAX ((add_t) -1)

/*!
 @brief Format of input file.
 */
enum input_format_t {
  /*!
   @brief Automatic guess of format.
   */
  AUTO_FORMAT = 0,

  /*!
   @brief File is a PE32 or PE32+ executable.
   */
  PE32_FORMAT,

  /*!
   @brief File is an ELF32 or ELF64 executable.
   */
  ELF_FORMAT,

  /*!
   @brief File is a raw dump of binary code.
   */
  RAW_FORMAT,

  /*!
   @brief File is a binary dump of an already extracted graph.
   */
  GRAPHBIN_FORMAT
};

/*!
 @brief Type of vector indexes (32bit).
 Vector cannot contains more than 2^32 elements.
 */
typedef uint32_t vsize_t;

#ifdef _MSC_VER
# define snprintf _snprintf
# define inline __inline
# define bzero(dst, size) memset(dst, 0, size);
#elif __MINGW32__
# define bzero(dst, size) memset(dst, 0, size);
#endif

/*!
 @brief Allocate an area capable of storing count object of type.
 */
#define MY_MALLOC(count, type) (type *)malloc((count)*sizeof(type))

/*!
 @brief Idem MY_MALLOC, but area is filled with zeros.
 */
#define MY_ZALLOC(count, type) (type *)calloc((count), sizeof(type))

/*!
 @brief Reallocate area addr to an area capable of storing count object of type.
 */
#define MY_REALLOC(addr, count, type) (type *)realloc(addr,(count)*sizeof(type))

/*!
 @brief Free allocated area addr.
 */
#define MY_FREE(addr) free(addr)

/*!
 @brief Fill with zero object dst.
 */
#define MY_BZERO(dst) bzero(dst, sizeof(*(dst)))

/*!
 @brief Used to allocate an array in the stack.
 Such allocation are automatically free'd at function return.
 */
#ifdef _MSC_VER
# include <malloc.h>
# define MY_ALLOCA(nb, type) (type *) _malloca((nb)*sizeof(type))
#else
# define MY_ALLOCA(nb, type) (type *) __builtin_alloca((nb)*sizeof(type))
#endif

#include "my_assert.h"
#endif
