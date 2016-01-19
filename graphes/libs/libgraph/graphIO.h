#ifndef GRAPHIO_H
#define GRAPHIO_H

#define GRAPHBINMAGIC "GRAPHBIN"
#define GRAPHBINMAGIC_LEN 8

#include "nodeIO.h"
#include "file_access.h"

/*!
 @file graphIO.h
 @brief Structure and methods for rooted and directed graphs input/output support.
 */
#include <stdio.h>

#include "graph.h"
#include "return_status.h"

graph_t *getGraphFromFile (FILE * f); // implemented in graphParser.c

/*!
 @brief Serialize a graph.
 @param graph The graph to serialize.
 @param fp The file to serialize the graph to.
 @return Number of written bytes.
 */
size_t graph_to_file (graph_t * graph, FILE * fp);

/*!
 @brief Read a graph from a serialization.
 @param pgraph The address where to store the newly malloc'd graph read from file
 @param fp The file where containing the serialization.
 @return Error status.
 */
status_t graph_from_file (graph_t ** pgraph, FILE * fp);

/*!
 @brief Print a a graph.
 @param graph The graph to print.
 @param fp The file to print the graph to.
 */
void graph_fprint (FILE * fp, graph_t * graph);

/*!
 @brief Test if file is a serialized graph.
 @param fp The file to test.
 @return Not null if file is a serialized graph.
 */
int is_graphbin_file (FILE * fp);

#endif 
