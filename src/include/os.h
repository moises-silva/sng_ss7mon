/*
 * Copyright (c) 2010, Sangoma Technologies
 * Moises Silva <msilva@sangoma.com>
 * All rights reserved.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 
 * * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 * 
 * * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 * 
 * * Neither the name of the original author; nor the names of any contributors
 * may be used to endorse or promote products derived from this software
 * without specific prior written permission.
 * 
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT OWNER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef __OS_H__
#define __OS_H__

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__linux__) && !defined(__USE_BSD)
#define __USE_BSD
#endif

#include "os_declare.h"
#include "os_threadmutex.h"
#include <string.h>
#include <stdlib.h>
#include <errno.h>

#ifndef __WINDOWS__
#include <unistd.h>
#endif

/*! \brief time data type */
typedef uint64_t os_time_t; 
/*! format string for os_time_t */
#define OS_TIME_FMT OS_UINT64_FMT

/*! \brief sleep x amount of milliseconds */
#ifdef __WINDOWS__
#define os_sleep(x) Sleep(x)
#else
#define os_sleep(x) usleep(x * 1000)
#endif

/*! \brief strncpy replacement */
#define os_copy_string(x,y,z) strncpy(x, y, z - 1)

/*! \brief strncpy into a fixed-length buffer */
#define os_set_string(x,y) strncpy(x, y, sizeof(x)-1)

/*! \brief check for null or zero length string buffer */
#define os_strlen_zero(s) (!s || *s == '\0')

/*! \brief check for zero length string buffer */
#define os_strlen_zero_buf(s) (*s == '\0')

/*! \brief array len helper */
#define os_array_len(array) sizeof(array)/sizeof(array[0])

/*! \brief Get smaller value */
#define os_min(x,y) ((x) < (y) ? (x) : (y))

/*! \brief Get larger value */
#define os_max(x,y) ((x) > (y) ? (x) : (y))

/*!
 * \brief Silence "unused parameter" compiler warnings
 * \note Tested with VS 2010, GCC 4.8, clang 3.1 and suncc
 * \code
 *	int example(char *a) {
 *		os_unused_arg(a);
 *		return 0;
 *	}
 * \endcode
 */
#define os_unused_arg(x) (void)(x)

/*!
  \brief Allocate uninitialized memory
  \param chunksize the chunk size
*/
#define os_malloc malloc

/*!
  \brief Reallocates memory
  \param buff the buffer
  \param chunksize the chunk size
*/
#define os_realloc realloc

/*!
  \brief Allocate initialized memory
  \param chunksize the chunk size
*/
#define os_calloc calloc

/*!
  \brief Free chunk of memory
  \param chunksize the chunk size
*/
#define os_free free

/*!
  \brief Free a pointer and set it to NULL unless it already is NULL
  \param it the pointer
*/
#define os_safe_free(it) if (it) { os_free(it); it = NULL; }

/*! \brief Duplicate string */
OS_DECLARE(char *) os_strdup(const char *str);

/*! \brief Duplicate string with limit */
OS_DECLARE(char *) os_strndup(const char *str, os_size_t inlen);

/*! \brief Get the current time in milliseconds */
OS_DECLARE(os_time_t) os_current_time_in_ms(void);

#ifdef __cplusplus
} /* extern C */
#endif

#endif

/* For Emacs:
 * Local Variables:
 * mode:c
 * indent-tabs-mode:t
 * tab-width:4
 * c-basic-offset:4
 * End:
 * For VIM:
 * vim:set softtabstop=4 shiftwidth=4 tabstop=4 noet:
 */
