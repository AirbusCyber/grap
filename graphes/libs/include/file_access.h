#ifndef FILE_ACCESS_H
#define FILE_ACCESS_H

/*!
 @file file_access.h
 @brief Method for reading and writting in little endian files without taking
 care of endianess of host.
 */
#include "ga_types.h"
#include "my_assert.h"
#include "swap.h"

#ifdef __BIG_ENDIAN__
#include <string.h> //memcpy
#endif

static inline size_t fread_le_swap_U64(uint64_t *dest, size_t count, FILE* fp) {
  size_t ret;

  ret = fread(dest, sizeof(uint64_t), count, fp);
#ifdef __BIG_ENDIAN__
  swap64_array(dest, count);
#endif
  return ret;
}

static inline size_t fread_le_swap_U32(uint32_t *dest, size_t count, FILE* fp) {
  size_t ret;

  ret = fread(dest, sizeof(uint32_t), count, fp);
#ifdef __BIG_ENDIAN__
  swap32_array(dest, count);
#endif
  return ret;
}

static inline size_t fread_le_swap_U16(uint16_t *dest, size_t count, FILE* fp) {
  size_t ret;

  ret = fread(dest, sizeof(uint16_t), count, fp);
#ifdef __BIG_ENDIAN__
  swap16_array(dest, count);
#endif
  return ret;
}

/*!
 @brief fread() like function that read a buffer from a little endian file by
 doing byte swapping on a big endian host.
 @param data A pointer to the destination buffer.
 @param size The size in byte of each element. Byte swapping is done on
 elements. Must be 1, 2, 4 or 8.
 @param count Number of element to read.
 @return Number of read elements, i.e. count if no problem occurs.
 */
static inline size_t fread_le_swap(void *data, size_t size, size_t count, FILE* stream) {
  switch (size) {
  case 8:
    return fread_le_swap_U64((uint64_t*) data, count, stream);
  case 4:
    return fread_le_swap_U32((uint32_t*) data, count, stream);
  case 2:
    return fread_le_swap_U16((uint16_t*) data, count, stream);
  case 1:
    return fread(data, sizeof(uint8_t), count, stream);
  default:
    MY_ASSERT_MSG(0, "Invalid read size");
    return 0;
  }
}

static inline size_t fwrite_le_swap_U64(const uint64_t *src, size_t count, FILE* fp) {
#ifdef __BIG_ENDIAN__
  size_t ret;
  uint64_t *buffer;

  buffer = MY_MALLOC(count, uint64_t);

  memcpy(buffer, src, count * sizeof(uint64_t));
  swap64_array(buffer, count);

  ret = fwrite(buffer, sizeof(uint64_t), count, fp);
  MY_FREE(buffer);
  return ret;
#else
  //printf("b4fwrite\n");
  return fwrite(src, sizeof(uint64_t), count, fp);
#endif
}

static inline size_t fwrite_le_swap_U32(const uint32_t *src, size_t count, FILE* fp) {
#ifdef __BIG_ENDIAN__
  size_t ret;
  uint32_t *buffer;

  buffer = MY_MALLOC(count, uint32_t);

  memcpy(buffer, src, count * sizeof(uint32_t));
  swap32_array(buffer, count);

  ret = fwrite(buffer, sizeof(uint32_t), count, fp);
  MY_FREE(buffer);
  return ret;
#else
  return fwrite(src, sizeof(uint32_t), count, fp);
#endif
}

static inline size_t fwrite_le_swap_U16(const uint16_t *src, size_t count, FILE* fp) {
#ifdef __BIG_ENDIAN__
  size_t ret;
  uint16_t *buffer;

  buffer = MY_MALLOC(count, uint16_t);

  memcpy(buffer, src, count * sizeof(uint16_t));
  swap16_array(buffer, count);

  ret = fwrite(buffer, sizeof(uint16_t), count, fp);
  MY_FREE(buffer);
  return ret;
#else
  return fwrite(src, sizeof(uint16_t), count, fp);
#endif
}

/*!
 @brief fwrite() like function that write a buffer into a little endian file by
 doing byte swapping on a big endian host.
 @param data A pointer to the data to write
 @param size The size in byte of each element of data. Byte swapping is done on
 elements. Must be 1, 2, 4 or 8.
 @param count Number of element in data.
 @return Number of written elements, i.e. count if no problem occurs.
 */
static inline size_t fwrite_le_swap(const void *data, size_t size, size_t count, FILE* stream) {
  switch (size) {
  case 8:
    return fwrite_le_swap_U64((uint64_t*) data, count, stream);
  case 4:
    return fwrite_le_swap_U32((uint32_t*) data, count, stream);
  case 2:
    return fwrite_le_swap_U16((uint16_t*) data, count, stream);
  case 1:
    return fwrite(data, sizeof(uint8_t), count, stream);
  default:
    MY_ASSERT_MSG(0, "Invalid read size");
    return 0;
  }
}
#endif
