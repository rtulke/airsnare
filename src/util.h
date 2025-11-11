/*
 * util.h - General utility functions and macros
 *
 * Provides helper functions and macros for common operations like
 * privilege management and string conversion.
 */

#ifndef ZZ_UTIL_H
#define ZZ_UTIL_H

#include "handler.h"

/* Macro to convert a preprocessor token to a string literal.
 * ZZ_STRING_BASE does the actual stringification, while ZZ_STRING
 * provides an extra layer of macro expansion. This two-step process
 * is necessary to properly expand macro arguments before stringifying. */
#define ZZ_STRING_BASE(x) #x
#define ZZ_STRING(x) ZZ_STRING_BASE(x)

/*
 * Drop root privileges after completing operations that require them
 * (e.g., opening network interfaces in monitor mode).
 *
 * Parameters:
 *   zz - Handler containing error buffer for reporting issues
 *
 * Returns:
 *   1 on success, 0 on failure (with error message set in zz->error_buffer)
 */
int zz_drop_root(zz_handler *zz);

#endif
