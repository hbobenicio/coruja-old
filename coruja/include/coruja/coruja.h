#ifndef CORUJA_H
#define CORUJA_H

void coruja_setup();
void coruja_cleanup();

int coruja_check_urls(const char** urls, size_t urls_length);
int coruja_parse_cert(const char* crt, size_t crt_size);

#endif // CORUJA_H
