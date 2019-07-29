//
// Created by explorer on 7/18/19.
//

#include "unit.h"
#include <unistd.h>
#include "log.h"
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/aes.h>

char *hex_set = "0123456789ABCDEF";

void read_size(int fd, unsigned char *buffer, unsigned int size) {
    unsigned int read_count = 0;
    int result;
    while (read_count != size) {
        result = (int) read(fd, buffer + read_count, size - read_count);
        if (result == 0) {
            logger(ERR, stderr, "peer if close");
            exit(1);
        }
        if (result == -1) {
            logger(ERR, stderr, "recv data error");
            exit(1);
        }
        read_count += result;
    }
}

void set_noblock(int fd) {
    int opts;
    opts = fcntl(fd, F_GETFL);
    if (opts < 0) {
        logger(ERR, stderr, "fcntl(F_GETFL: %s)\n", strerror(errno));
        exit(1);
    }
    if (fcntl(fd, F_SETFL, opts | O_NONBLOCK) < 0) {
        logger(ERR, stderr, "fcntl(F_SETFD) %s\n", strerror(errno));
        exit(1);
    }
}

void b2hex(const unsigned char *in_buf, unsigned int size, char *out_buf) {     // BUG: off by one
    unsigned int i;
    for (i = 0; i < size; i++) {
        out_buf[2 * i] = hex_set[in_buf[i] >> 4];
        out_buf[2 * i + 1] = hex_set[in_buf[i] & 0xf];
    }
    out_buf[2 * i] = '\x00';
}


char *hex(const unsigned char *in_buf, unsigned int size) {     // BUG: off by one
    unsigned int i;
    char *out_buf = malloc(size * 2 + 1);
    for (i = 0; i < size; i++) {
        out_buf[2 * i] = hex_set[in_buf[i] >> 4];
        out_buf[2 * i + 1] = hex_set[in_buf[i] & 0xf];
    }
    out_buf[2 * i] = '\x00';
    return out_buf;
}


// just a wrap
void sha256(unsigned char *data, unsigned int data_size, unsigned char *md) {
    SHA256(data, data_size, md);
}


// aes_cbc_pkcs5
void
aes_enc(unsigned char *data, unsigned int data_size, unsigned char *out, unsigned char *key,
        unsigned char *iv) {
    AES_KEY enc_key;
    AES_set_encrypt_key(key, AES_BLOCK_SIZE * 8, &enc_key);
    AES_cbc_encrypt(data, out, data_size, &enc_key, iv, AES_ENCRYPT);
}

void
aes_dec(unsigned char *data, unsigned int data_size, unsigned char *out, unsigned char *key,
        unsigned char *iv) {
    AES_KEY dec_key;
    AES_set_decrypt_key(key, AES_BLOCK_SIZE * 8, &dec_key);
    AES_cbc_encrypt(data, out, data_size, &dec_key, iv, AES_DECRYPT);
}

unsigned char seed[32];
int seed_init = 0;

void init_random() {
    FILE *fd;
    fd = fopen("/dev/urandom", "r");
    if (fd == NULL) {
        logger(ERR, stderr, "urandom open failed");
        exit(0);
    }
    fread(seed, 32, 1, fd);
    fclose(fd);
}

void random_byte(unsigned char *buffer, unsigned int size) {
    int i;
    unsigned char seed2[32];
    if (!seed_init) {
        init_random();
    }
    for (i = 0; i < (int) (size - 32); i += 32) {
        memcpy(buffer + i, seed, 32);
        sha256(buffer + i, 32, seed);
    }
    memcpy(buffer + i, seed, size - i);
    memcpy(seed2, seed, 32);
    sha256(seed2, 32, seed);
}