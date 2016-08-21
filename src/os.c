#include "os.h"
#include <sys/types.h>
#include <sys/stat.h>

#ifdef __linux__
#include <unistd.h>
#endif

const char *OS_LOG_LEVEL_NAMES[9] = {
	"EMERG",
	"ALERT",
	"CRIT",
	"ERROR",
	"WARNING",
	"NOTICE",
	"INFO",
	"DEBUG",
	NULL
};

static int os_log_level = OS_LOG_LEVEL_DEBUG;

static void default_logger(const char *file, const char *func, int line, int level, const char *fmt, ...);

OS_DECLARE_DATA os_logger_t os_log = default_logger;

static void default_logger(const char *file, const char *func, int line, int level, const char *fmt, ...)
{
	char data[1024];
	va_list ap;

	if (level < 0 || level > 7) {
		level = 7;
	}
	if (level > os_log_level) {
		return;
	}

	va_start(ap, fmt);

	vsnprintf(data, sizeof(data), fmt, ap);

	fprintf(stderr, "[%s] %s:%d %s() %s", OS_LOG_LEVEL_NAMES[level], file, line, func, data);

	va_end(ap);

}

OS_DECLARE(char *) os_strdup(const char *str)
{
	os_size_t len = strlen(str) + 1;
	void *new = os_malloc(len);
	if (!new) {
		return NULL;
	}
	return (char *)memcpy(new, str, len);
}

#ifdef WIN32
// clock_gettime() Windows implementation (not really, but good enough for us)
// from http://stackoverflow.com/questions/5404277/porting-clock-gettime-to-windows
static LARGE_INTEGER getFILETIMEoffset()
{
	SYSTEMTIME s;
	FILETIME f;
	LARGE_INTEGER t;

	s.wYear = 1970;
	s.wMonth = 1;
	s.wDay = 1;
	s.wHour = 0;
	s.wMinute = 0;
	s.wSecond = 0;
	s.wMilliseconds = 0;
	SystemTimeToFileTime(&s, &f);
	t.QuadPart = f.dwHighDateTime;
	t.QuadPart <<= 32;
	t.QuadPart |= f.dwLowDateTime;
	return (t);
}

OS_DECLARE(int) os_clock_gettime(struct timeval *tv)
{
	LARGE_INTEGER t;
	FILETIME f;
	double microseconds;
	static LARGE_INTEGER offset;
	static int initialized = 0;

	if (!initialized) {
		initialized = 1;
		offset = getFILETIMEoffset();
	}
	GetSystemTimeAsFileTime(&f);
	t.QuadPart = f.dwHighDateTime;
	t.QuadPart <<= 32;
	t.QuadPart |= f.dwLowDateTime;
	t.QuadPart -= offset.QuadPart;
	microseconds = (double)t.QuadPart / 10;
	t.QuadPart = microseconds;
	tv->tv_sec = t.QuadPart / 1000000;
	tv->tv_usec = t.QuadPart % 1000000;
	return (0);
}

OS_DECLARE(int) os_fstat(FILE *f, os_stat_t *buf)
{
	return _fstat(_fileno(f), buf);
}

#else
OS_DECLARE(int) os_clock_gettime(struct timeval *tv)
{
	struct timespec ts;
	int ret = clock_gettime(CLOCK_REALTIME, &ts);
	tv->tv_sec = ts.tv_sec;
	tv->tv_usec = (ts.tv_nsec / 1000);
	return ret;
}

OS_DECLARE(int) os_fstat(FILE *f, os_stat_t *buf)
{
	return fstat(fileno(f), buf);
}
#endif
