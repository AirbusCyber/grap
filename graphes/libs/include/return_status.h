#ifndef RETURN_STATUS_H
#define RETURN_STATUS_H

typedef enum {
  STATUS_OK = 0,
  STATUS_FILE_NOT_FOUND,
  STATUS_UNKNOWN_FORMAT,
  STATUS_INVALID_FILE,
  STATUS_GRAPH_TOO_SMALL,
  STATUS_LAST //must be the last
} enum_status_t;

typedef uint32_t status_t;

#endif
