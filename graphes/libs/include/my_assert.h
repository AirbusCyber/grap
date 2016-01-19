#ifndef MY_ASSERT_H
#define MY_ASSERT_H

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

#define Segfault      (++*(int *)0)
#define Continue

#define AssertSignal  Segfault
#define AssertStream  stderr

#ifdef ENABLE_ASSERT
#define AssertActionMsg(...)                                                \
  do {                                                                      \
    fprintf(AssertStream,"%s:%d (%s) : ",__FILE__,__LINE__,__FUNCTION__);   \
    fprintf(AssertStream,__VA_ARGS__);                                      \
    fprintf(AssertStream,"\n");                                             \
    AssertSignal;                                                           \
  }while(0)

#define AssertActionMsgContinue(...)                                                \
  do {                                                                      \
    fprintf(AssertStream,"%s:%d (%s) : ",__FILE__,__LINE__,__FUNCTION__);   \
    fprintf(AssertStream,__VA_ARGS__);                                      \
    fprintf(AssertStream,"\n");                                             \
  }while(0)

#define MY_ASSERT(cond)                                                     \
  do {                                                                      \
    if(unlikely(!(cond)))                                                   \
      AssertActionMsg("failed");                                            \
  } while(0)

#define MY_ASSERT_MSG(cond, ...)                                            \
  do {                                                                      \
    if(unlikely(!(cond)))                                                   \
      AssertActionMsg(__VA_ARGS__);                                         \
  } while(0)

#define MY_ASSERT_MSG_CONTINUE(cond, ...)                                            \
  do {                                                                      \
    if(unlikely(!(cond)))                                                   \
      AssertActionMsgContinue(__VA_ARGS__);                                         \
  } while(0)
#else /* ENABLE_ASSERT */

#define MY_ASSERT(cond)
#define MY_ASSERT_MSG(cond, ...)
#define MY_ASSERT_MSG_CONTINUE(cond, ...)

#endif /* ENABLE_ASSERT */

#endif
