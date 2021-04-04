#include <string.h>
#include <stdio.h>
#include <assert.h>

#include "address.h"
#include <coruja/log.h>

bool coruja_address_parse(const char* input, CorujaAddress* out_address) {
    assert(out_address != NULL);

    if (strchr(input, ':') != NULL) {
        // dynamic format string for safe usage and consistent usage of sscanf
        //char format[100];
        //snprintf(format, sizeof(format), "%[^:]%%ds:%%%ds", MAX_HOST_SIZE, MAX_PORT_SIZE);
        //int fields_read = sscanf(input, "%[^:]s:%6s", out_address->host, out_address->port);

        size_t bytes_read = parse_hostname(input, out_address->host);
        // TODO check if ok!
        input += bytes_read;

        bytes_read = skip_char(input, ':');
        // TODO check if ok!
        input += bytes_read;

        bytes_read = parse_port(input, out_address->port);
        // TODO check if ok!
        input += bytes_read;
        // TODO check if input == '\0'; (empty string) or strlen(input) == 0;

        coruja_log_info("host: %s", out_address->host);
        coruja_log_info("port: %s", out_address->port);
        //coruja_log_info("fields_read: %d", fields_read);
        return fields_read == 2 ? true : false;
    }
    
    strncpy(out_address->host, input, MAX_HOST_SIZE);
    strncpy(out_address->port, "443", MAX_PORT_SIZE);
    return true;
}
