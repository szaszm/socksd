#include "Logger.h"

#include <assert.h>
#include <stdio.h>
#include <errno.h> // errno
#include <string.h> // strerror
#include <stdarg.h> // va_start, va_end, vs_list
#include <stdlib.h> // malloc

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
	if(level == LOG_LEVEL_ALL) {
		int i;
		for(i = 0; i < 6; ++i) {
			_this->logger_functions[i] = fn;
			_this->data[i] = data;
		}
	} else {
		_this->logger_functions[level] = fn;
		_this->data[level] = data;
	}
}

void Logger_setMinLevel(struct Logger *_this, enum LogLevel level) {
	_this->min_level = level;
}

static const char* Logger_getLogLevelPrefix(enum LogLevel level) {
	switch (level) {
		case LOG_LEVEL_ERROR:   return "[ERROR]   ";
		case LOG_LEVEL_WARNING: return "[WARNING] ";
		case LOG_LEVEL_INFO:    return "[INFO]    ";
		case LOG_LEVEL_VERBOSE: return "[VERBOSE] ";
		case LOG_LEVEL_DEBUG:   return "[DEBUG]   ";
		case LOG_LEVEL_ALL:
		case LOG_LEVEL_QUIET:   break;
	}
	return "[UNKNOWN] ";
}

void Logger_log(const struct Logger *_this, enum LogLevel level, const char *domain, const char *fmt, ...) {
	if(level > _this->min_level || !_this->logger_functions[level]) return;
	va_list args;
	va_start(args, fmt);
	char message[MSG_MAXLEN + 1];
	vsnprintf(message, sizeof(message), fmt, args);
	va_end(args);

	const char *const level_str = Logger_getLogLevelPrefix(level);
	const size_t level_str_len = strlen(level_str);
	if (domain) {
		const size_t ld_len = level_str_len + strlen(domain);
		char* const level_and_domain = (char*)malloc(ld_len + 1);
		assert(level_and_domain);
		memset(level_and_domain, 0, ld_len + 1);
		strncat(level_and_domain, level_str, ld_len);
		strncat(level_and_domain, domain, ld_len - level_str_len);
		_this->logger_functions[level](_this->data[level], level_and_domain, message);
		free(level_and_domain);
	} else {
		_this->logger_functions[level](_this->data[level], level_str, message);
	}
}

void Logger_perror(const struct Logger *_this, enum LogLevel level, const char *domain) {
	Logger_log(_this, level, domain, strerror(errno));
}
