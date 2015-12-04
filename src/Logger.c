#include "Logger.h"
#include <stdio.h>
#include <errno.h> // errno
#include <string.h> // strerror

#ifdef ARRAY_LENGTH
#undef ARRAY_LENGTH
#endif
#define ARRAY_LENGTH(a) (sizeof(a)/sizeof(*(a)))

#define MSG_MAXLEN 1024

void LOGGER_FUNCTION_DEFAULT_STDERR(const char *domain, const char *message) {
	fprintf(stderr, "%s: %s\n", domain, message);
}

void LOGGER_FUNCTION_DEFAULT_STDOUT(const char *domain, const char *message) {
	fprintf(stdout, "%s: %s\n", domain, message);
}

struct Logger Logger_init(enum LogLevel min_level) {
	struct Logger res;
	res.min_level = min_level;
	size_t i;
	for(i = 0; i < ARRAY_LENGTH(res.logger_functions); ++i) {
		if(i <= LOG_LEVEL_WARNING) {
			res.logger_functions[i] = LOGGER_FUNCTION_DEFAULT_STDERR;
		} else {
			res.logger_functions[i] = LOGGER_FUNCTION_DEFAULT_STDOUT;
		}
	}
	return res;
}

void Logger_setLoggerFunction(struct Logger *_this, enum LogLevel level, void (*fn)(const char *,const char *)) {
	_this->logger_functions[level] = fn;
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
	_this->logger_functions[level](domain, message);
}

void Logger_perror(const struct Logger *_this, enum LogLevel level, const char *domain) {
	Logger_log(_this, level, domain, strerror(errno));
}
