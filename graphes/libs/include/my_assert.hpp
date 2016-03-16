#ifndef MY_ASSERT_H
#define MY_ASSERT_H

#ifndef NDEBUG
#define ENABLE_ASSERT
#endif

#include <stdio.h>

#ifndef likely
# ifdef _MSC_VER
#  define likely(x)   (x)
# else
#  define likely(x)   __builtin_expect(!!(x), 1)
# endif
#endif

#ifndef unlikely
# ifdef _MSC_VER
#  define unlikely(x) (x)
# else
# define unlikely(x)  __builtin_expect(!!(x), 0)
#endif
#endif

#define AssertStream  stderr

#define AssertActionMsg(...)                                                \
  do {                                                                      \
    fprintf(AssertStream,__VA_ARGS__);                                      \
    fprintf(AssertStream,"\n");                                             \
    exit(EXIT_FAILURE);                                                     \
  }while(0)

#ifdef ENABLE_ASSERT
#define AssertActionMsgContinue(...)                                        \
  do {                                                                      \
    fprintf(AssertStream,__VA_ARGS__);                                      \
    fprintf(AssertStream,"\n");                                             \
  }while(0)

#define ASSERT_MSG(cond, ...)                                               \
  do {                                                                      \
    if(unlikely(!(cond)))                                                   \
      AssertActionMsg(__VA_ARGS__);                                         \
  } while(0)

#define ASSERT_MSG_CONTINUE(cond, ...)                                      \
  do {                                                                      \
    if(unlikely(!(cond)))                                                   \
      AssertActionMsgContinue(__VA_ARGS__);                                 \
  } while(0)
#else /* ENABLE_ASSERT */

#define ASSERT_MSG(cond, ...)
#define ASSERT_MSG_CONTINUE(cond, ...)

#endif /* ENABLE_ASSERT */

#define RELEASE_ASSERT(cond)                                                \
  do {                                                                      \
    if(unlikely(!(cond)))                                                   \
      AssertActionMsg("Fatal error.");                                      \
  } while(0)

#endif
