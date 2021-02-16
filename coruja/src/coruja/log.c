#include <stdio.h>
#include <time.h>

#include <coruja/ansi.h>
#include <coruja/log.h>

void coruja_log_info(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    time_t now_raw_time;
    time(&now_raw_time);

    struct tm* now = localtime(&now_raw_time);

    // TODO 3 IO's em FILE's não bufferizados? We can do it better...
    fprintf(stderr, CORUJA_BRIGHT_GREEN_BOLD "[%04d-%02d-%02d %02d:%02d:%02d] [info] " CORUJA_ANSI_GFX_RESET,
        now->tm_year + 1900,
        now->tm_mday,
        now->tm_mon + 1,
        now->tm_hour,
        now->tm_min,
        now->tm_sec
    );
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");

    va_end(args);
}

void coruja_log_warn(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    time_t now_raw_time;
    time(&now_raw_time);

    struct tm* now = localtime(&now_raw_time);

    fprintf(stderr, CORUJA_BRIGHT_YELLOW_BOLD "[%04d-%02d-%02d %02d:%02d:%02d] [warn] " CORUJA_ANSI_GFX_RESET,
        now->tm_year + 1900,
        now->tm_mday,
        now->tm_mon + 1,
        now->tm_hour,
        now->tm_min,
        now->tm_sec
    );
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");

    va_end(args);
}

void coruja_log_error(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);

    time_t now_raw_time;
    time(&now_raw_time);

    struct tm* now = localtime(&now_raw_time);

    fprintf(stderr, CORUJA_BRIGHT_RED_BOLD "[%04d-%02d-%02d %02d:%02d:%02d] [error] " CORUJA_ANSI_GFX_RESET,
        now->tm_year + 1900,
        now->tm_mday,
        now->tm_mon + 1,
        now->tm_hour,
        now->tm_min,
        now->tm_sec
    );
    vfprintf(stderr, fmt, args);
    fprintf(stderr, "\n");

    va_end(args);
}
