#ifndef LOGGER_H
#define LOGGER_H

enum LogLevel { LOG_LEVEL_QUIET = 0, LOG_LEVEL_ERROR, LOG_LEVEL_WARNING, LOG_LEVEL_INFO, LOG_LEVEL_VERBOSE, LOG_LEVEL_DEBUG };
struct Logger {
	void (*logger_functions[6])(const char *domain, const char *message);
	enum LogLevel min_level;
};

// Default logging functions to print messages to standard output and error streams
void LOGGER_FUNCTION_DEFAULT_STDERR(const char *domain, const char *message);
void LOGGER_FUNCTION_DEFAULT_STDOUT(const char *domain, const char *message);

struct Logger Logger_init(enum LogLevel min_level);
void Logger_setLoggerFunction(struct Logger *, enum LogLevel, void (*fn)(const char *domain,const char *message));
void Logger_setMinLevel(struct Logger *, enum LogLevel);
void Logger_log(const struct Logger *, enum LogLevel, const char *domain, const char *msgfmt, ...);
void Logger_perror(const struct Logger *, enum LogLevel, const char *domain);

#define Logger_error(logger, ...) Logger_log((logger), LOG_LEVEL_ERROR, __VA_ARGS__)
#define Logger_warn(logger, ...) Logger_log((logger), LOG_LEVEL_WARNING, __VA_ARGS__)
#define Logger_info(logger, ...) Logger_log((logger), LOG_LEVEL_INFO, __VA_ARGS__)
#define Logger_verbose(logger, ...) Logger_log((logger), LOG_LEVEL_VERBOSE, __VA_ARGS__)
#define Logger_debug(logger, ...) Logger_log((logger), LOG_LEVEL_DEBUG, __VA_ARGS__)

#endif /* LOGGER_H */
