#ifndef LIBGTSI_H
#define LIBGTSI_H

#include <stdio.h>
#include "Traversal.hpp"
#include "utils-gtsi.h"
#include <unordered_set>

extern "C" {
#include "graphIO.h"
}

// char optionFuncs;
// char optionLabels;
char* labCharToString(vsize_t label);
#endif
