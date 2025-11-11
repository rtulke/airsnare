/*
 * endian.h - Byte order conversion compatibility layer
 *
 * Provides a unified interface for byte order conversion functions across
 * different platforms (Linux and macOS). This ensures that network protocol
 * data structures (IEEE 802.11, radiotap, etc.) are correctly interpreted
 * regardless of the host's native byte order.
 */

#ifndef ZZ_ENDIAN
#define ZZ_ENDIAN

#ifdef __linux__

/* Linux provides standard endian.h with conversion functions */
#include <endian.h>

#elif __APPLE__

/* macOS uses OSByteOrder API, so we define compatibility macros
 * to match the Linux endian.h interface */
#include <libkern/OSByteOrder.h>

/* 16-bit conversions */
#define htobe16(x) OSSwapHostToBigInt16(x)      /* host to big-endian */
#define htole16(x) OSSwapHostToLittleInt16(x)   /* host to little-endian */
#define be16toh(x) OSSwapBigToHostInt16(x)      /* big-endian to host */
#define le16toh(x) OSSwapLittleToHostInt16(x)   /* little-endian to host */

/* 32-bit conversions */
#define htobe32(x) OSSwapHostToBigInt32(x)      /* host to big-endian */
#define htole32(x) OSSwapHostToLittleInt32(x)   /* host to little-endian */
#define be32toh(x) OSSwapBigToHostInt32(x)      /* big-endian to host */
#define le32toh(x) OSSwapLittleToHostInt32(x)   /* little-endian to host */

/* 64-bit conversions */
#define htobe64(x) OSSwapHostToBigInt64(x)      /* host to big-endian */
#define htole64(x) OSSwapHostToLittleInt64(x)   /* host to little-endian */
#define be64toh(x) OSSwapBigToHostInt64(x)      /* big-endian to host */
#define le64toh(x) OSSwapLittleToHostInt64(x)   /* little-endian to host */

#endif

#endif
