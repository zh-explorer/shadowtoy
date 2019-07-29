//
// Created by explorer on 7/18/19.
//

#ifndef SHDOWTOY_UNIT_H
#define SHDOWTOY_UNIT_H

#define SHA256_DIGEST_LENGTH 32

void read_size(int fd, unsigned char *buffer, unsigned int size);

void set_noblock(int fd);

void sha256(unsigned char *data, unsigned int data_size, unsigned char *md);

void b2hex(const unsigned char *in_buf, unsigned int size, char *out_buf);

void
aes_enc(unsigned char *data, unsigned int data_size, unsigned char *out, unsigned char *key,
        unsigned char *iv);

void
aes_dec(unsigned char *data, unsigned int data_size, unsigned char *out, unsigned char *key,
        unsigned char *iv);

void random_byte(unsigned char *buffer, unsigned int size);

char *hex(const unsigned char *in_buf, unsigned int size);

#endif //SHDOWTOY_UNIT_H
