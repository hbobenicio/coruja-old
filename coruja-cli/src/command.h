#ifndef CORUJA_CLI_COMMAND_H
#define CORUJA_CLI_COMMAND_H

#include "globals.h"

typedef enum {
    CORUJA_CLI_COMMAND_INVALID,
    CORUJA_CLI_COMMAND_HELP,
    CORUJA_CLI_COMMAND_CHECK,
    CORUJA_CLI_COMMAND_DOWNLOAD,
} Command;

typedef struct {
    const char* urls[MAX_ARGS];
    size_t urls_length;
} CommandCheckArgs;

typedef struct {
    const char* urls[MAX_ARGS];
    size_t urls_length;
} CommandDownloadArgs;

#endif
