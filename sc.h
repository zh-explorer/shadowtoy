//
// Created by explorer on 7/19/19.
//

#ifndef SHDOWTOY_SC_H
#define SHDOWTOY_SC_H

#include <netinet/in.h>

int sc_server(int fd);

int sc_client(int addr_type, unsigned char *ip, unsigned char ip_size, in_port_t port);

extern char *password;

typedef struct {
    unsigned char token[16];
    time_t timestamp;
    unsigned char noise[8];
    unsigned char main_version;
    uint32_t length;
    unsigned char random_len;
    unsigned char padding[10];
    unsigned char hash_sum[32];
    unsigned char data[1];
} __attribute__ ((packed)) sc_package;

int check_replay(time_t timestemp, const unsigned char *noise);

void enc_packet(unsigned char *data, unsigned int size, unsigned char **output, unsigned *out_size);

#endif //SHDOWTOY_SC_H
