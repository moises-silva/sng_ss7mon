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

#ifndef __OS_DECLARE_H__
#define __OS_DECLARE_H__

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_XOPEN_SOURCE) && !defined(__FreeBSD__)
#define _XOPEN_SOURCE 600
#endif

#ifndef HAVE_STRINGS_H
#define HAVE_STRINGS_H 1
#endif
#ifndef HAVE_SYS_SOCKET_H
#define HAVE_SYS_SOCKET_H 1
#endif

#ifndef __WINDOWS__
#if defined(WIN32) || defined(WIN64) || defined(_MSC_VER) || defined(_WIN32) || defined(_WIN64)
#define __WINDOWS__
#define WIN32
#endif
#endif

#ifdef _MSC_VER
#define __OS_FUNC__ __FUNCTION__
#if defined(OS_DECLARE_STATIC)
#define OS_DECLARE(type)			type __stdcall
#define OS_DECLARE_NONSTD(type)		type __cdecl
#define OS_DECLARE_DATA
#elif defined(OS_EXPORTS)
#define OS_DECLARE(type)			__declspec(dllexport) type __stdcall
#define OS_DECLARE_NONSTD(type)		__declspec(dllexport) type __cdecl
#define OS_DECLARE_DATA				__declspec(dllexport)
#else
#define OS_DECLARE(type)			__declspec(dllimport) type __stdcall
#define OS_DECLARE_NONSTD(type)		__declspec(dllimport) type __cdecl
#define OS_DECLARE_DATA				__declspec(dllimport)
#endif
#define OS_DECLARE_INLINE(type)		extern __inline__ type /* why extern? see http://support.microsoft.com/kb/123768 */
#define EX_DECLARE_DATA				__declspec(dllexport)
#else
#define __OS_FUNC__ (const char *)__func__
#if (defined(__GNUC__) || defined(__SUNPRO_CC) || defined (__SUNPRO_C)) && defined(HAVE_VISIBILITY)
#define OS_DECLARE(type)		__attribute__((visibility("default"))) type
#define OS_DECLARE_NONSTD(type)	__attribute__((visibility("default"))) type
#define OS_DECLARE_DATA		__attribute__((visibility("default")))
#else
#define OS_DECLARE(type)		type
#define OS_DECLARE_NONSTD(type)	type
#define OS_DECLARE_DATA
#endif
#define OS_DECLARE_INLINE(type)		__inline__ type
#define EX_DECLARE_DATA
#endif

#ifdef _MSC_VER
#ifndef __inline__
#define __inline__ __inline
#endif
#if (_MSC_VER >= 1400)			/* VC8+ */
#ifndef _CRT_SECURE_NO_DEPRECATE
#define _CRT_SECURE_NO_DEPRECATE
#endif
#ifndef _CRT_NONSTDC_NO_DEPRECATE
#define _CRT_NONSTDC_NO_DEPRECATE
#endif
#endif
#ifndef strcasecmp
#define strcasecmp(s1, s2) _stricmp(s1, s2)
#endif
#ifndef strncasecmp
#define strncasecmp(s1, s2, n) _strnicmp(s1, s2, n)
#endif
#if _MSC_VER < 1900
#define snprintf _snprintf
#endif
#ifndef S_IRUSR
#define S_IRUSR _S_IREAD
#endif
#ifndef S_IWUSR
#define S_IWUSR _S_IWRITE
#endif
#undef HAVE_STRINGS_H
#undef HAVE_SYS_SOCKET_H
/* disable warning for zero length array in a struct */
/* this will cause errors on c99 and ansi compliant compilers and will need to be fixed in the wanpipe header files */
#pragma warning(disable:4706)
#pragma comment(lib, "Winmm")
#endif

/*
 * Compiler-specific format checking attributes
 * use these on custom functions that use printf/scanf-style
 * format strings (e.g. os_log())
 */
#if defined(__GNUC__)
/**
 * Enable compiler-specific printf()-style format and argument checks on a function
 * @param	fmtp	Position of printf()-style format string parameter
 * @param	argp	Position of variable argument list ("...") parameter
 * @code
 *	void log(const int level, const char *fmt, ...) __os_check_printf(2, 3);
 * @endcode
 */
#define __os_check_printf(fmtp, argp) __attribute__((format (printf, fmtp, argp)))
/**
 * Enable compiler-specific scanf()-style format and argument checks on a function
 * @param	fmtp	Position of scanf()-style format string parameter
 * @param	argp	Position of variable argument list ("...") parameter
 * @code
 *	void parse(struct foo *ctx, const char *fmt, ...) __os_check_scanf(2, 3);
 * @endcode
 */
#define __os_check_scanf(fmtp, argp) __attribute__((format (scanf, fmtp, argp)))
#else
#define __os_check_printf(fmtp, argp)
#define __os_check_scanf(fmtp, argp)
#endif

#ifdef __WINDOWS__
#include <stdio.h>
#include <time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <winsock2.h>
#include <windows.h>
#define OS_INVALID_SOCKET INVALID_HANDLE_VALUE
typedef HANDLE os_socket_t;
typedef unsigned __int64 uint64_t;
typedef unsigned __int32 uint32_t;
typedef unsigned __int16 uint16_t;
typedef unsigned __int8 uint8_t;
typedef __int64 int64_t;
typedef __int32 int32_t;
typedef __int16 int16_t;
typedef __int8 int8_t;
#define OS_O_BINARY O_BINARY
#define OS_SIZE_FMT "Id"
#define OS_INT64_FMT "lld"
#define OS_UINT64_FMT "llu"
#define OS_XINT64_FMT "llx"
#if defined(_MSC_VER) || defined(_MSC_EXTENSIONS)
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000Ui64
#else
#define DELTA_EPOCH_IN_MICROSECS  11644473600000000ULL
#endif /* _MSC_VER */
#else /* __WINDOWS__ */
#define OS_O_BINARY 0
#define OS_SIZE_FMT "zd"
#if (defined(__SIZEOF_LONG__) && (__SIZEOF_LONG__ == 8)) || defined(__LP64__) || defined(__LLP64__)
#define OS_INT64_FMT "ld"
#define OS_UINT64_FMT "lu"
#define OS_XINT64_FMT "lx"
#else
#define OS_INT64_FMT "lld"
#define OS_UINT64_FMT "llu"
#define OS_XINT64_FMT "llx"
#endif
#define OS_INVALID_SOCKET -1
typedef int os_socket_t;
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#endif

typedef size_t os_size_t;

/*! \brief OS API possible return codes */
typedef enum {
    OS_SUCCESS, /*!< Success */
    OS_FAIL, /*!< Failure, generic error return code when no more specific return code can be used */

    OS_MEMERR, /*!< Allocation failure */
    OS_ENOMEM = OS_MEMERR,

    OS_TIMEOUT, /*!< Operation timed out (ie: polling on a device)*/
    OS_ETIMEDOUT = OS_TIMEOUT,

    OS_NOTIMPL, /*!< Operation not implemented */
    OS_ENOSYS = OS_NOTIMPL, /*!< The function is not implemented */

    OS_BREAK, /*!< Request the caller to perform a break (context-dependant, ie: stop getting DNIS/ANI) */

    /*!< Any new return codes should try to mimc unix style error codes, no need to reinvent */
    OS_EINVAL, /*!< Invalid argument */
    OS_ECANCELED, /*!< Operation cancelled */
    OS_EBUSY, /*!< Device busy */
} os_status_t;

/* Logging is not strictly OS, but kinda */
#define OS_PRE __FILE__, __func__, __LINE__
#define OS_LOG_LEVEL_DEBUG 7
#define OS_LOG_LEVEL_INFO 6
#define OS_LOG_LEVEL_NOTICE 5
#define OS_LOG_LEVEL_WARNING 4
#define OS_LOG_LEVEL_ERROR 3
#define OS_LOG_LEVEL_CRIT 2
#define OS_LOG_LEVEL_ALERT 1
#define OS_LOG_LEVEL_EMERG 0

/*! \brief Log levels  */
#define OS_LOG_DEBUG OS_PRE, OS_LOG_LEVEL_DEBUG
#define OS_LOG_INFO OS_PRE, OS_LOG_LEVEL_INFO
#define OS_LOG_NOTICE OS_PRE, OS_LOG_LEVEL_NOTICE
#define OS_LOG_WARNING OS_PRE, OS_LOG_LEVEL_WARNING
#define OS_LOG_ERROR OS_PRE, OS_LOG_LEVEL_ERROR
#define OS_LOG_CRIT OS_PRE, OS_LOG_LEVEL_CRIT
#define OS_LOG_ALERT OS_PRE, OS_LOG_LEVEL_ALERT
#define OS_LOG_EMERG OS_PRE, OS_LOG_LEVEL_EMERG

/*! \brief Logging function prototype to be used for all logs
 *  you should use os_set_logger to set your own logger
 */
typedef void (*os_logger_t)(const char *file, const char *func, int line, int level, const char *fmt, ...) __os_check_printf(5, 6);
OS_DECLARE_DATA extern os_logger_t os_log;
OS_DECLARE(void) os_set_logger(os_logger_t logger);

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
