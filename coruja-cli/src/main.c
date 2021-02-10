#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include <coruja/coruja.h>
#include <coruja/log.h>

#include "globals.h"
#include "command.h"

static void validate_args(int argc, char** argv);
static void usage_print();

static Command parse_command(int argc, char** argv);
static int parse_command_check(int argc, char** argv, CommandCheckArgs* out_args);
static int parse_command_download(int argc, char** argv, CommandDownloadArgs* out_args);

static void do_command_check(CommandCheckArgs* args);
static void do_command_download(CommandDownloadArgs* args);

int main(int argc, char** argv) {
    // CLI Input Validation / Parsing
    validate_args(argc, argv);
    
    // We already validated above that there is at least a command string (first argument).
    // Check it if it's valid or not.
    Command command = parse_command(argc, argv);
    if (command == CORUJA_CLI_COMMAND_INVALID) {
        coruja_log_error("invalid command '%s'.\n", argv[1]);
        usage_print();
        return EXIT_FAILURE;
    }

    coruja_setup();
    
    switch (command) {
    case CORUJA_CLI_COMMAND_HELP:
        // TODO this could be improved to provide help for the subcommands
        usage_print();
        coruja_cleanup();
        return EXIT_SUCCESS;

    case CORUJA_CLI_COMMAND_CHECK: {
        CommandCheckArgs args = {0};
        parse_command_check(argc, argv, &args);
        do_command_check(&args);
        break;
    }

    case CORUJA_CLI_COMMAND_DOWNLOAD: {
        CommandDownloadArgs args = {0};
        parse_command_download(argc, argv, &args);
        do_command_download(&args);
        break;
    }
    
    default:
        coruja_log_error("unimplemented command '%s'", argv[1]);
        coruja_cleanup();
        return EXIT_FAILURE;
    }
    
    coruja_cleanup();
}

/**
 * @returns 0 if valid
 */
static void validate_args(int argc, char** argv) {
    if (argc < 2) {
        usage_print();
        exit(EXIT_FAILURE);
    }
    if (argc - 1 > MAX_ARGS) {
        coruja_log_error("argument overflow. Max value (%d) exceeded", MAX_ARGS);
        exit(EXIT_FAILURE);
    }
}

static void usage_print() {
    printf("USAGE:\n");
    printf("    coruja check <HOST>[:<PORT>] [<HOST>[:<PORT>] ...]\t\t- Verifica certificados TLS dos servidores\n");
    printf("    coruja download <HOST>[:<PORT>] [<HOST>[:<PORT>] ...]\t- Baixa certificados TLS dos servidores\n\n");
    printf("EXAMPLES:\n");
    printf("    coruja check google.com github.com:443\n\n");
}

static Command parse_command(int argc, char** argv) {
    const char* input_command = argv[1];

    if (strncmp(input_command, "help", sizeof "help") == 0) {
        return CORUJA_CLI_COMMAND_HELP;
    }

    if (strncmp(input_command, "check", sizeof "check") == 0) {
        return CORUJA_CLI_COMMAND_CHECK;
    }

    if (strncmp(input_command, "download", sizeof "download") == 0) {
        return CORUJA_CLI_COMMAND_DOWNLOAD;
    }

    return CORUJA_CLI_COMMAND_INVALID;
}

static int parse_command_check(int argc, char** argv, CommandCheckArgs* out_args) {
    size_t url_count = 0;
    for (int i = 2; i < argc; i++, url_count++) {
        out_args->urls[i - 2] = argv[i];
    }
    out_args->urls_length = url_count;
    return 0;
}

static int parse_command_download(int argc, char** argv, CommandDownloadArgs* out_args) {
    return 0;
}

static void do_command_check(CommandCheckArgs* args) {
    coruja_check_urls(args->urls, args->urls_length);
}

static void do_command_download(CommandDownloadArgs* args) {

}
