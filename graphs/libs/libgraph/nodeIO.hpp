#ifndef NODEIO_H
#define NODEIO_H

/*!
 @file nodeIO.h
 @brief Input/Output support for nodes.
 */

#include <stdio.h>
#include "node.hpp"

/*!
 @brief Print a node in format .dot.
 @param node Source node.
 @param node Root node.
 @param fp Destination file.
 @return Number of written bytes.
 */
size_t node_to_dot(const node_t* node, const node_t* root, size_t, FILE* fp);

/*!
 @brief Print all edges going out of a node in format .dot.
 @param node Source node.
 @param fp Destination file.
 @return Number of written bytes.
 */
size_t node_edges_to_dot(const node_t* node, FILE* fp);

int printVK(FILE * fp, char *key, char *value, char virg);
int printVKint(FILE * fp, char *key, int value, char virg);

#endif
