#ifndef SWAP_H
#define SWAP_H

/* Swap macros */
#define SWAP16(x) ((uint16_t)((((uint16_t)(x) & 0xFF00) >> 8) | \
							  (((uint16_t)(x) & 0x00FF) << 8)))

#if defined(__GNUC__) && (__GNUC__ > 3) && (__GNUC__ > 4 || __GNUC_MINOR__ >= 3)
# define SWAP32(x) __builtin_bswap32(x)
# define SWAP64(x) __builtin_bswap64(x)
#else
# define SWAP32(x) ((uint32_t)((((uint32_t)(x) & 0xFF000000) >> 24) | \
							  (((uint32_t)(x) & 0x00FF0000) >>  8) | \
							  (((uint32_t)(x) & 0x0000FF00) <<  8) | \
							  (((uint32_t)(x) & 0x000000FF) << 24)))

# define SWAP64(x) ((uint64_t)((((uint64_t)(x) & 0xFF00000000000000ULL) >> 56) | \
							  (((uint64_t)(x) & 0x00FF000000000000ULL) >> 40) | \
							  (((uint64_t)(x) & 0x0000FF0000000000ULL) >> 24) | \
							  (((uint64_t)(x) & 0x000000FF00000000ULL) >>  8) | \
							  (((uint64_t)(x) & 0x00000000FF000000ULL) <<  8) | \
							  (((uint64_t)(x) & 0x0000000000FF0000ULL) << 24) | \
							  (((uint64_t)(x) & 0x000000000000FF00ULL) << 40) | \
							  (((uint64_t)(x) & 0x00000000000000FFULL) << 56)))
#endif

#ifndef __BIG_ENDIAN__
# if defined(__ppc__) || defined(__ppc64__)
#  define __BIG_ENDIAN__ 1
# endif
#endif

#ifndef __LITTLE_ENDIAN__
# if defined(__i386__) || defined(__amd64__) || defined(_MSC_VER) || defined(__BORLANDC__) || defined(__CYGWIN__)
#  define __LITTLE_ENDIAN__ 1
# endif
#endif

#ifndef __LITTLE_ENDIAN__
# ifndef __BIG_ENDIAN__
#  error architecture not supported
# endif
#endif

/* Helper macros */
#ifdef __BIG_ENDIAN__
# define HOST_TO_BE16(x)	((uint16_t)(x))
# define HOST_TO_BE32(x)	((uint32_t)(x))
# define HOST_TO_BE64(x)	((uint64_t)(x))

# define HOST_TO_LE16(x)	SWAP16(x)
# define HOST_TO_LE32(x)	SWAP32(x)
# define HOST_TO_LE64(x)	SWAP64(x)

# define BE16_TO_HOST(x)	((uint16_t)(x))
# define BE32_TO_HOST(x)	((uint32_t)(x))
# define BE64_TO_HOST(x)	((uint64_t)(x))

# define LE16_TO_HOST(x)	SWAP16(x)
# define LE32_TO_HOST(x)	SWAP32(x)
# define LE64_TO_HOST(x)	SWAP64(x)
#endif

#ifdef __LITTLE_ENDIAN__
# define HOST_TO_BE16(x)	SWAP16(x)
# define HOST_TO_BE32(x)	SWAP32(x)
# define HOST_TO_BE64(x)	SWAP64(x)

# define HOST_TO_LE16(x)	((uint16_t)(x))
# define HOST_TO_LE32(x)	((uint32_t)(x))
# define HOST_TO_LE64(x)	((uint64_t)(x))

# define BE16_TO_HOST(x)	SWAP16(x)
# define BE32_TO_HOST(x)	SWAP32(x)
# define BE64_TO_HOST(x)	SWAP64(x)

# define LE16_TO_HOST(x)	((uint16_t)(x))
# define LE32_TO_HOST(x)	((uint32_t)(x))
# define LE64_TO_HOST(x)	((uint64_t)(x))
#endif

/* Array functions */
static inline void swap64_array(uint64_t *data, size_t count) {
  while (count--) {
    data[count] = SWAP64(data[count]);
  }
}

static inline void swap32_array(uint32_t *data, size_t count) {
  while (count--) {
    data[count] = SWAP32(data[count]);
  }
}

static inline void swap16_array(uint16_t *data, size_t count) {
  while (count--) {
    data[count] = SWAP16(data[count]);
  }
}

#endif
