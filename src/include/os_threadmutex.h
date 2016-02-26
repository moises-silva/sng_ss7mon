/* 
 * Cross Platform Thread/Mutex abstraction
 * Copyright(C) 2007 Michael Jerris
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so.
 *
 * This work is provided under this license on an "as is" basis, without warranty of any kind,
 * either expressed or implied, including, without limitation, warranties that the covered code
 * is free of defects, merchantable, fit for a particular purpose or non-infringing. The entire
 * risk as to the quality and performance of the covered code is with you. Should any covered
 * code prove defective in any respect, you (not the initial developer or any other contributor)
 * assume the cost of any necessary servicing, repair or correction. This disclaimer of warranty
 * constitutes an essential part of this license. No use of any covered code is authorized hereunder
 * except under this disclaimer. 
 *
 * Contributors: 
 *
 * Moises Silva <msilva@sangoma.com>
 *
 */


#ifndef _OS_THREADMUTEX_H
#define _OS_THREADMUTEX_H

#include "os.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct os_mutex os_mutex_t;
typedef struct os_thread os_thread_t;
typedef void *(*os_thread_function_t) (os_thread_t *, void *);

OS_DECLARE(os_status_t) os_thread_create(os_thread_function_t func, void *data, os_thread_t **newthread);
OS_DECLARE(os_status_t) os_thread_create_ex(os_thread_function_t func, void *data, os_size_t stack_size, os_thread_t **newthread);
OS_DECLARE(os_status_t) os_thread_create_detached(os_thread_function_t func, void *data);
OS_DECLARE(os_status_t) os_thread_create_detached_ex(os_thread_function_t func, void *data, os_size_t stack_size);
OS_DECLARE(void) os_thread_override_default_stacksize(os_size_t size);
OS_DECLARE(os_status_t) os_thread_join(os_thread_t *thread);

OS_DECLARE(os_status_t) os_mutex_create(os_mutex_t **mutex);
OS_DECLARE(os_status_t) os_mutex_destroy(os_mutex_t **mutex);

#define os_mutex_lock(_x) _os_mutex_lock(__FILE__, __LINE__, __OS_FUNC__, _x)
OS_DECLARE(os_status_t) _os_mutex_lock(const char *file, int line, const char *func, os_mutex_t *mutex);

#define os_mutex_trylock(_x) _os_mutex_trylock(__FILE__, __LINE__, __OS_FUNC__, _x)
OS_DECLARE(os_status_t) _os_mutex_trylock(const char *file, int line, const char *func, os_mutex_t *mutex);

#define os_mutex_unlock(_x) _os_mutex_unlock(__FILE__, __LINE__, __OS_FUNC__, _x)
OS_DECLARE(os_status_t) _os_mutex_unlock(const char *file, int line, const char *func, os_mutex_t *mutex);

#ifdef __cplusplus
}
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

