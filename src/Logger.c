#include "Logger.h"
#include <stdio.h>
#include <errno.h> // errno
#include <string.h> // strerror

#ifdef ARRAY_LENGTH
#undef ARRAY_LENGTH
#endif
#define ARRAY_LENGTH(a) (sizeof(a)/sizeof(*(a)))

// http://stackoverflow.com/questions/3599160/unused-parameter-warnings-in-c-code
#define UNUSED(x) (void)(x)

#define MSG_MAXLEN 1024

void LOGGER_FUNCTION_DEFAULT_STDERR(void *unused, const char *domain, const char *message) {
	UNUSED(unused);
	fprintf(stderr, "%s: %s\n", domain, message);
}

void LOGGER_FUNCTION_DEFAULT_STDOUT(void *unused, const char *domain, const char *message) {
	UNUSED(unused);
	fprintf(stdout, "%s: %s\n", domain, message);
}

void LOGGER_FUNCTION_LOG_TO_FILE(void *file_pointer, const char *domain, const char *message) {
	fprintf((FILE *)file_pointer, "%s: %s\n", domain, message);
}

struct Logger Logger_init(enum LogLevel min_level) {
	struct Logger res;
	res.min_level = min_level;
	size_t i;
	for(i = 0; i < ARRAY_LENGTH(res.logger_functions); ++i) {
		if(i <= LOG_LEVEL_WARNING) {
			res.logger_functions[i] = LOGGER_FUNCTION_DEFAULT_STDERR;
			res.data[i] = stderr;
		} else {
			res.logger_functions[i] = LOGGER_FUNCTION_DEFAULT_STDOUT;
			res.data[i] = stderr;
		}
	}
	return res;
}

void Logger_setLoggerFunction(struct Logger *_this, enum LogLevel level, void (*fn)(void *,const char *,const char *), void *data) {
	_this->logger_functions[level] = fn;
	_this->data[level] = data;
}

void Logger_setMinLevel(struct Logger *_this, enum LogLevel level) {
	_this->min_level = level;
}

void Logger_log(const struct Logger *_this, enum LogLevel level, const char *domain, const char *fmt, ...) {
	if(level > _this->min_level || !_this->logger_functions[level]) return;
	va_list args;
	va_start(args, fmt);
	char message[MSG_MAXLEN + 1];
	vsnprintf(message, sizeof(message), fmt, args);
	va_end(args);
	_this->logger_functions[level](_this->data[level], domain, message);
}

void Logger_perror(const struct Logger *_this, enum LogLevel level, const char *domain) {
	Logger_log(_this, level, domain, strerror(errno));
}
