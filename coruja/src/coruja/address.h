#ifndef CORUJA_ADDRESS_H
#define CORUJA_ADDRESS_H

#include <stdbool.h>

#define MAX_HOST_SIZE 150
#define MAX_PORT_SIZE 6

typedef struct {
    char host[MAX_HOST_SIZE + 1];
    char port[MAX_PORT_SIZE + 1];
} CorujaAddress;

bool coruja_address_parse(const char* input, CorujaAddress* out_address);

#endif
