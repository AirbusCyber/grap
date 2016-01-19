#ifndef LIBGRAPHBINALGO_H
#define LIBGRAPHBINALGO_H

#ifdef __CYGWIN__
#include <sys/time.h>
#endif

#ifdef WIN32
# include <winsock2.h>
typedef HANDLE pthread_t;
# define THREAD_FUNC DWORD WINAPI
#else
# include <pthread.h>
# include <inttypes.h>
# include <sys/time.h> /* gettimeofday */
#define THREAD_FUNC void *
#endif

#include <semaphore.h>
#include <stdlib.h>
#include "graphIO.h"
//#include "graph_import.h"
//#include "reduction.h"
//#include "node_ptr_list.h"
//#include "nodeTL.h"
//#include "input_extract.h"
//#include <time.h>


#if defined (WIN32) || defined (__CYGWIN__)
# define HAVE_DOS_BASED_FILE_SYSTEM
# define IS_DIR_SEPARATOR(ch) \
  (((ch) == '/') || ((ch) == '\\'))
# define SEPARATOR '\\'
#else
# define IS_DIR_SEPARATOR(ch) ((ch) == '/')
# define SEPARATOR '/'
#endif

// const char * basename(const char * name) {
//   const char *base;
// 
// #if defined (HAVE_DOS_BASED_FILE_SYSTEM)
//   /* Skip over the disk name in MSDOS pathnames. */
//   if (isalpha (name[0]) && name[1] == ':')
//   name += 2;
// #endif
// 
//   for (base = name; *name; name++) {
//     if (IS_DIR_SEPARATOR (*name)) {
//       base = name + 1;
//     }
//   }
//   return base;
// }

char* Red;
char* Green;
char* Color_Off;
char optionMCSByPattern;
char optionMCS;
char optionNoPerm;
char optionCheckSymb;
char optionCount;
char optionRedInt;
char optionRec;
char optionQuiet;
char optionVerbose;
char optionOutSmall;
char optionExport;
char optionMultiThreaded;
char optionForceRoots;
char optionIsoOnly;
char optionDebug;
char optionInfo;
char optionOnlyInduced;
char optionLabels;
int nThreads;

FILE* FILEeP;
FILE* FILEeT;
FILE* FILEenP;
FILE* FILEenT;
FILE* FILEesP;
FILE* FILEesT;

sem_t mutexExport;
sem_t mutexIsoTotal;
sem_t mutexnSgraphP;
sem_t mutexStructRead;
sem_t mutexBSFPattern;
char* isThreadBusy;

int maxFound;
int maxPatternFound;
int isoTotal;
int wP;
int wT;
int nSgraphP;

struct structProcessGraph{
   graph_t* grPattern;
   vsize_t debutPattern;
   vsize_t finPattern;
   vsize_t tailleTest;
   graph_t** graphsToTest;
};

// int main(int, char**);
int pcharcmp(char* c1, char* c2, int size);
void* processSubGraphs(void* grData);
void createGraphs(void);
int isoUllman(graph_t*, graph_t*);
void debugPrintF(vsize_t*, vsize_t);
void debugPrintM(char*, vsize_t, vsize_t);
int backtrack(graph_t* grPattern, graph_t* grToTest, char* M0, vsize_t j, vsize_t nPattern, vsize_t nToTest, vsize_t limit, vsize_t* F, vsize_t Fmax, char* assignedPattern, char* assignedToTest, vsize_t lastAssignedPatternPlusOne, node_list_t* listP, node_list_t* listT, char only_induced);
void forbidPerm(graph_t*, graph_t*, char*, vsize_t, vsize_t, vsize_t, vsize_t*, int);
int forwardChecking(graph_t* grPattern, graph_t* grToTest, char* Mp, vsize_t j, vsize_t nPattern, vsize_t nToTest, vsize_t* F, vsize_t Fmax, char* assignedPattern, char* assignedToTest, node_list_t* listP, node_list_t* listT, char only_induced);
//char Flk(vsize_t, vsize_t, vsize_t*, vsize_t);
char E(node_t*, node_t*);
char Elw(node_t*, node_t*);
char Ekv(node_t*, node_t*);
char Ewl(node_t*, node_t*);
char Evk(node_t*, node_t*);
graph_t* BFS_gba(graph_t* inputGraph, vsize_t vroot, vsize_t R);
char* BFS2(graph_t* inputGraph, vsize_t vroot, vsize_t R);
int computeInterval(graph_t* inputGraph, node_t* head, node_t** interval, int nInterval);
char isNodeIn(node_t* node, node_t** interval, int nRow, int maxI);
graph_t* reduceInterval(graph_t* graph);

#endif
