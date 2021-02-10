#ifndef CORUJA_LOG_H
#define CORUJA_LOG_H

#include <stdarg.h>

void coruja_log_info(const char* fmt, ...);
void coruja_log_warn(const char* fmt, ...);
void coruja_log_error(const char* fmt, ...);

#endif
