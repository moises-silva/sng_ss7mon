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

#ifdef WIN32
#   if (_WIN32_WINNT < 0x0400)
#       error "Need to target at least Windows 95/WINNT 4.0 because TryEnterCriticalSection is needed"
#   endif
#   include <windows.h>
#endif
/*#define OS_DEBUG_MUTEX 0*/

#include "os_threadmutex.h"

#ifdef WIN32
#include <process.h>

#define OS_THREAD_CALLING_CONVENTION __stdcall

struct os_mutex {
	CRITICAL_SECTION mutex;
};

#else
#include <pthread.h>
#include <poll.h>

#define OS_THREAD_CALLING_CONVENTION

#ifdef OS_DEBUG_MUTEX
#define OS_MUTEX_MAX_REENTRANCY 30
typedef struct os_lock_entry {
	const char *file;
	const char *func;
	uint32_t line;
} os_lock_entry_t;

typedef struct os_lock_history {
	os_lock_entry_t locked;
	os_lock_entry_t unlocked;
} os_lock_history_t;
#endif

struct os_mutex {
	pthread_mutex_t mutex;
#ifdef OS_DEBUG_MUTEX
	os_lock_history_t lock_history[OS_MUTEX_MAX_REENTRANCY];
	uint8_t reentrancy;
#endif
};

#endif

struct os_thread {
#ifdef WIN32
	void *handle;
#else
	pthread_t handle;
#endif
	void *private_data;
	os_thread_function_t function;
	os_size_t stack_size;
#ifndef WIN32
	pthread_attr_t attribute;
#endif
};

os_size_t thread_default_stacksize = 0;

OS_DECLARE(void) os_thread_override_default_stacksize(os_size_t size)
{
	thread_default_stacksize = size;
}

static void * OS_THREAD_CALLING_CONVENTION thread_launch(void *args)
{
	void *exit_val;
	os_thread_t *thread = (os_thread_t *)args;
	exit_val = thread->function(thread, thread->private_data);
#ifndef WIN32
	pthread_attr_destroy(&thread->attribute);
#endif
	os_safe_free(thread);

	return exit_val;
}

OS_DECLARE(os_status_t) os_thread_create_detached(os_thread_function_t func, void *data)
{
	return os_thread_create_detached_ex(func, data, thread_default_stacksize);
}

OS_DECLARE(os_status_t) os_thread_create_detached_ex(os_thread_function_t func, void *data, os_size_t stack_size)
{
	os_thread_t *thread = NULL;
	os_status_t status = OS_FAIL;

	if (!func || !(thread = (os_thread_t *)os_calloc(1, sizeof(os_thread_t)))) {
		goto done;
	}

	thread->private_data = data;
	thread->function = func;
	thread->stack_size = stack_size;

#if defined(WIN32)
	thread->handle = (void *)_beginthreadex(NULL, (unsigned)thread->stack_size, (unsigned int (__stdcall *)(void *))thread_launch, thread, 0, NULL);
	if (!thread->handle) {
		goto fail;
	}
	CloseHandle(thread->handle);

	status = OS_SUCCESS;
	goto done;
#else
	
	if (pthread_attr_init(&thread->attribute) != 0)	goto fail;

	if (pthread_attr_setdetachstate(&thread->attribute, PTHREAD_CREATE_DETACHED) != 0) goto failpthread;

	if (thread->stack_size && pthread_attr_setstacksize(&thread->attribute, thread->stack_size) != 0) goto failpthread;

	if (pthread_create(&thread->handle, &thread->attribute, thread_launch, thread) != 0) goto failpthread;

	status = OS_SUCCESS;
	goto done;
 failpthread:
	pthread_attr_destroy(&thread->attribute);
#endif

 fail:
	if (thread) {
		os_safe_free(thread);
	}
 done:
	return status;
}


OS_DECLARE(os_status_t) os_mutex_create(os_mutex_t **mutex)
{
	os_status_t status = OS_FAIL;
#ifndef WIN32
	pthread_mutexattr_t attr;
#endif
	os_mutex_t *check = NULL;

	check = (os_mutex_t *)os_calloc(1, sizeof(**mutex));
	if (!check)
		goto done;
#ifdef WIN32
	InitializeCriticalSection(&check->mutex);
#else
	if (pthread_mutexattr_init(&attr))
		goto done;

	if (pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE))
		goto fail;

	if (pthread_mutex_init(&check->mutex, &attr))
		goto fail;

	goto success;

 fail:
	pthread_mutexattr_destroy(&attr);
	goto done;

 success:
#endif
	*mutex = check;
	status = OS_SUCCESS;

 done:
	return status;
}

OS_DECLARE(os_status_t) os_mutex_destroy(os_mutex_t **mutex)
{
	os_mutex_t *mp = *mutex;
	*mutex = NULL;
	if (!mp) {
		return OS_FAIL;
	}
#ifdef WIN32
	DeleteCriticalSection(&mp->mutex);
#else
	if (pthread_mutex_destroy(&mp->mutex))
		return OS_FAIL;
#endif
	os_safe_free(mp);
	return OS_SUCCESS;
}

#define ADD_LOCK_HISTORY(mutex, file, line, func) \
	{ \
		if ((mutex)->reentrancy < OS_MUTEX_MAX_REENTRANCY) { \
			(mutex)->lock_history[mutex->reentrancy].locked.file = (file); \
			(mutex)->lock_history[mutex->reentrancy].locked.func = (func); \
			(mutex)->lock_history[mutex->reentrancy].locked.line = (line); \
			(mutex)->lock_history[mutex->reentrancy].unlocked.file = NULL; \
			(mutex)->lock_history[mutex->reentrancy].unlocked.func = NULL; \
			(mutex)->lock_history[mutex->reentrancy].unlocked.line = 0; \
			(mutex)->reentrancy++; \
			if ((mutex)->reentrancy == OS_MUTEX_MAX_REENTRANCY) { \
				os_log((file), (func), (line), OS_LOG_LEVEL_ERROR, "Max reentrancy reached for mutex %p\n", (mutex)); \
			} \
		} \
	}

OS_DECLARE(os_status_t) _os_mutex_lock(const char *file, int line, const char *func, os_mutex_t *mutex)
{
#ifdef WIN32
	os_unused_arg(file);
	os_unused_arg(line);
	os_unused_arg(func);

	EnterCriticalSection(&mutex->mutex);
#else
	int err;
	if ((err = pthread_mutex_lock(&mutex->mutex))) {
		os_log(file, func, line, OS_LOG_LEVEL_ERROR, "Failed to lock mutex %d:%s\n", err, strerror(err));
		return OS_FAIL;
	}
#endif
#ifdef OS_DEBUG_MUTEX
	ADD_LOCK_HISTORY(mutex, file, line, func);
#endif
	return OS_SUCCESS;
}

OS_DECLARE(os_status_t) _os_mutex_trylock(const char *file, int line, const char *func, os_mutex_t *mutex)
{
	os_unused_arg(file);
	os_unused_arg(line);
	os_unused_arg(func);
#ifdef WIN32
	if (!TryEnterCriticalSection(&mutex->mutex))
		return OS_FAIL;
#else
	if (pthread_mutex_trylock(&mutex->mutex))
		return OS_FAIL;
#endif
#ifdef OS_DEBUG_MUTEX
	ADD_LOCK_HISTORY(mutex, file, line, func);
#endif
	return OS_SUCCESS;
}

OS_DECLARE(os_status_t) _os_mutex_unlock(const char *file, int line, const char *func, os_mutex_t *mutex)
{
#ifdef OS_DEBUG_MUTEX
	int i = 0;
	if (mutex->reentrancy == 0) {
		os_log(file, func, line, OS_LOG_LEVEL_ERROR, "Cannot unlock something that is not locked!\n");
		return OS_FAIL;
	}
	i = mutex->reentrancy - 1;
	/* I think this is a fair assumption when debugging */
	if (func != mutex->lock_history[i].locked.func) {
		os_log(file, func, line, OS_LOG_LEVEL_WARNING, "Mutex %p was suspiciously locked at %s->%s:%d but unlocked at %s->%s:%d!\n",
				mutex, mutex->lock_history[i].locked.func, mutex->lock_history[i].locked.file, mutex->lock_history[i].locked.line, 
				func, file, line);
	}
	mutex->lock_history[i].unlocked.file = file;
	mutex->lock_history[i].unlocked.line = line;
	mutex->lock_history[i].unlocked.func = func;
	mutex->reentrancy--;
#endif
#ifdef WIN32
	os_unused_arg(file);
	os_unused_arg(line);
	os_unused_arg(func);

	LeaveCriticalSection(&mutex->mutex);
#else
	if (pthread_mutex_unlock(&mutex->mutex)) {
		os_log(file, func, line, OS_LOG_LEVEL_ERROR, "Failed to unlock mutex: %s\n", strerror(errno));
#ifdef OS_DEBUG_MUTEX
		mutex->reentrancy++;
#endif
		return OS_FAIL;
	}
#endif
	return OS_SUCCESS;
}


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
