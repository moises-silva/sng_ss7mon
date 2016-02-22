#include "os.h"

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
