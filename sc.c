//
// Created by explorer on 7/19/19.
//

#include "sc.h"
#include "netio.h"
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include "log.h"
#include "unit.h"
#include <time.h>
#include <openssl/sha.h>

#define SERVER_IP "127.0.0.1"
#define SERVER_PORT 8888

#define BLCOK_SIZE 1024

char *password = "meiyoumima";


typedef struct {
    int fd;
    unsigned char *buffer;
    unsigned int data_size;
    unsigned int buffer_size;
} sc_ctx;

typedef struct noise_node {
    time_t t;
    uint64_t noise;
    struct noise_node *next;
} noise_node;

noise_node *time_array[300];

char *errmsg(int err);

void sc_init(sc_ctx *ctx, int fd);

void read_size_sc(sc_ctx *ctx, unsigned char *buffer, unsigned int size);

void write_and_clean(sc_ctx *ctx, int peer_fd);

void sc_resp_err(int fd, unsigned char err_code, in_addr_t ip, in_port_t port) {
    unsigned char buf[9], *enc_data;
    unsigned int enc_data_size;
    buf[0] = 2;
    buf[1] = err_code;
    buf[2] = 1;
    memcpy(buf + 3, &ip, 4);
    memcpy(buf + 7, &port, 2);

    enc_packet(buf, 9, &enc_data, &enc_data_size);
    write(fd, enc_data, enc_data_size);
    free(enc_data);
    close(fd);
    exit(0);
}

int sc_client(int addr_type, unsigned char *ip, unsigned char ip_size, in_port_t port) {
    int client_fd;
    unsigned char *req, *enc_data;
    unsigned char resp[9];
    unsigned int req_len, enc_data_size;
    sc_ctx ctx;
    client_fd = tcp_conn(inet_addr(SERVER_IP), htons(SERVER_PORT));
    if (client_fd < 0) {
        //connection error
        logger(ERR, stderr, "sc_client conn to %s:%d err", SERVER_IP, SERVER_PORT);
        return client_fd;
    }
    if (addr_type == 1) {
        req_len = 9;
        req = malloc(req_len);
        req[0] = 1;
        req[1] = 1;
        req[2] = 1;
        memcpy(req + 3, ip, 4);
        memcpy(req + 7, &port, 2);

    } else if (addr_type == 3) {
        req_len = 5 + 1 + ip_size;
        req = malloc(req_len);
        req[0] = 1;
        req[1] = 1;
        req[2] = 3;
        req[3] = ip_size;
        memcpy(req + 4, ip, ip_size);
        memcpy(req + 4 + ip_size, &port, 2);
        free(ip);
    } else {
        logger(ERR, stderr, "unknown addr type");
        close(client_fd);
        return -1;
    }

    enc_packet(req, req_len, &enc_data, &enc_data_size);
    write(client_fd, enc_data, enc_data_size);
    free(enc_data);

    // the remote only resp 4 byte ipv4 addr type now

    sc_init(&ctx, client_fd);
    read_size_sc(&ctx, resp, 9);

    if (resp[0] != 2) {
        logger(ERR, stderr, "unknown proto type");
        close(client_fd);
        return -1;
    } else if (resp[1] != 0) {
        logger(ERR, stderr, "conn error %s", errmsg(resp[1]));
        close(client_fd);
        return -1;
    }
    free(req);
    // wo ignore remote ip/port

    return client_fd;
}

int sc_server(int fd) {
    unsigned char in_buffer[0x100], out_buf[0x100], *enc_data;
    int addr_type;
    unsigned int addr_len, enc_data_size;
    in_addr_t ip, s_ip;
    in_port_t port, s_port;
    unsigned char url_size = 0;
    struct sockaddr_in addr;
    struct hostent *host;
    char *url = 0;
    int client_fd, result;
    sc_ctx ctx;

    alarm(30); // server proto must finish in 30 sec

    sc_init(&ctx, fd);

    read_size_sc(&ctx, in_buffer, 3);

    if (in_buffer[0] != 1) {
        logger(ERR, stderr, "unknown proto type");
        close(fd);
        exit(0);
    }
    if (in_buffer[1] != 1) {
        logger(ERR, stderr, "unknown cmd type");
        close(fd);
        exit(0);
    }
    if (in_buffer[2] != 1 && in_buffer[2] != 3) {
        logger(ERR, stderr, "unknown addr type");
        close(fd);
        exit(0);
    }
    addr_type = in_buffer[2];
    if (addr_type == 1) {
        read_size_sc(&ctx, (unsigned char *) &ip, 4);
        read_size_sc(&ctx, (unsigned char *) &port, 2);
    } else {

        read_size_sc(&ctx, &url_size, 1);
        url = malloc(url_size + 1);
        memset(url, 0, url_size + 1);

        read_size_sc(&ctx, (unsigned char *) url, url_size);
        read_size_sc(&ctx, (unsigned char *) &port, 2);

        host = gethostbyname(url);
        if (host == NULL || host->h_addrtype == AF_INET6) {
            // host lookup error
            sc_resp_err(fd, 8, 0, 0);
        }
        memcpy(&ip, host->h_addr, 4);

    }

    if (addr_type == 1) {
        struct in_addr tmp;
        tmp.s_addr = ip;
        logger(INFO, stderr, "get  sc req to %s:%d", inet_ntoa(tmp), ntohs(port));
    } else {
        logger(INFO, stderr, "get  sc req to %s:%d", url, ntohs(port));
        free(url);
    }
    client_fd = tcp_conn(ip, port);
    if (client_fd < 0) {
        logger(ERR, stderr, "conn error %s", strerror(errno));
        sc_resp_err(fd, 1, 0, 0);
    }


    addr_len = sizeof(addr);
    result = getsockname(fd, (struct sockaddr *) &addr, (socklen_t *) &addr_len);
    if (result == -1) {
        logger(ERR, stderr, "error on get peer name");
        sc_resp_err(fd, 0xff, 0, 0);
    }

    s_ip = addr.sin_addr.s_addr;
    s_port = addr.sin_port;

    out_buf[0] = 2;
    out_buf[1] = 0;
    out_buf[2] = 1;
    memcpy(out_buf + 3, &s_ip, 4);
    memcpy(out_buf + 7, &s_port, 2);

    enc_packet(out_buf, 9, &enc_data, &enc_data_size);
    write(fd, enc_data, enc_data_size);
    free(enc_data);
//    write_and_clean(&ctx, client_fd);

    // server connection success, canceled alarm;
    alarm(0);

    return client_fd;
}

char *errmsg(int err) {
    switch (err) {
        case 1:
            return "network unreachable";
        case 2:
            return "cmd unknown";
        case 3:
            return "ip addr error";
        case 4:
            return "unknown error";
        default:
            return "unknown error code";
    }
}

void enc_packet(unsigned char *data, unsigned int size, unsigned char **output, unsigned *out_size) {
    SHA256_CTX ctx;
    unsigned char buf[32];
    sc_package *out_buf;
    time_t timestamp = time(NULL);
    unsigned char noise[8];
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned char random_len;
    unsigned char pad = (unsigned char) (16 - size % 16);
    unsigned int length;
    int i;
    unsigned char key[16];
    unsigned char iv[16];


    random_byte(&random_len, 1);
    random_len = random_len % 80;
    length = 80 + size + pad + random_len;
    out_buf = malloc(length);
    memset(out_buf, 0, length);

    out_buf->length = length;
    out_buf->timestamp = time(NULL);
    random_byte(out_buf->noise, 8);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, password, strlen(password));
    SHA256_Update(&ctx, &out_buf->timestamp, 8);
    SHA256_Update(&ctx, out_buf->noise, 8);
    SHA256_Final(md, &ctx);

    memcpy(out_buf->token, md, 16);
    out_buf->main_version = 1;
    out_buf->random_len = random_len;
    random_byte(out_buf->padding, 10);

    memcpy(out_buf->data, data, size);
    for (i = 0; i < pad; i++) {
        out_buf->data[size + i] = pad;
    }

    random_byte(out_buf->data + size + pad, random_len);

    sha256((unsigned char *) out_buf, length, md);

    memcpy(out_buf->hash_sum, md, 32);

    SHA256_Init(&ctx);
    SHA256_Update(&ctx, password, strlen(password));
    SHA256_Update(&ctx, out_buf->token, 16);
    SHA256_Final(md, &ctx);

//    sha256((unsigned char *) out_buf, 16, md);
    memcpy(key, md, 16);
    memcpy(iv, md + 16, 16);

    *output = malloc(length);
    *out_size = length;
    memset(*output, 0, length);
    aes_enc((unsigned char *) out_buf + 16, length - 16 - random_len, (*output) + 16, key, iv);
    memcpy(*output, out_buf->token, 16);
    memcpy(*output + length - random_len, out_buf->data + size + pad, out_buf->random_len);


    free(out_buf);
//    free(data);
}

int check_replay(time_t timestemp, const unsigned char *noise) {
    int idx = (int) (timestemp % 300);
    noise_node *p, *prev = NULL;
    p = time_array[idx];
    if (timestemp + 300 < time(NULL)) {
        return 0;
    }
    while (p) {
        if (p->t + 300 < time(NULL)) {
            // unlink this
            if (prev == NULL) {
                time_array[idx] = p->next;
                free(p);
                p = time_array[idx];
                continue;
            } else {
                prev->next = p->next;
                free(p);
                p = prev->next;
            }
        }
        if (p->noise == *(uint64_t *) noise) {
            return -1;
        } else {
            prev = p;
            p = p->next;
        }
    }
    p = malloc(sizeof(noise_node));
    memset(p, 0, sizeof(noise_node));
    if (prev) {
        prev->next = p;
    } else {
        time_array[idx] = p;
    }
    p->next = NULL;
    p->noise = *(uint64_t *) noise;
    p->t = timestemp;
    return 0;
}

void sc_init(sc_ctx *ctx, int fd) {
    memset(ctx, 0, sizeof(sc_ctx));
    ctx->fd = fd;
    ctx->buffer_size = BLCOK_SIZE;
    ctx->buffer = malloc(BLCOK_SIZE);
}

void write_and_clean(sc_ctx *ctx, int peer_fd) {
    write(peer_fd, ctx->buffer, ctx->data_size);
    free(ctx->buffer);
}

void read_sc_pack(sc_ctx *ctx) {
    sc_package *pack = malloc(sizeof(sc_package));
    sc_package *dec_pack = malloc(sizeof(sc_package));
    int fd = ctx->fd;
    unsigned char *rand_data;
//    unsigned char token[16];
    unsigned char md[SHA256_DIGEST_LENGTH];
    unsigned char key[16];
    unsigned char iv[16];
    unsigned int data_size;                 
    unsigned char *enc_data;
    unsigned char pad;
    SHA256_CTX *sha256_ctx = malloc(sizeof(SHA256_CTX));
//    time_t timestamp;
//    unsigned char noise[16];

    memset(pack, 0, sizeof(sc_package));
    memset(dec_pack, 0, sizeof(sc_package));

    read_size(fd, dec_pack->token, 16);

    SHA256_Init(sha256_ctx);
    SHA256_Update(sha256_ctx, password, strlen(password));
    SHA256_Update(sha256_ctx, dec_pack->token, 16);
    SHA256_Final(md, sha256_ctx);

    memcpy(key, md, 16);
    memcpy(iv, md + 16, 16);

    read_size(fd, (unsigned char *) &pack->timestamp, 8);
    read_size(fd, pack->noise, 8);

    aes_dec((unsigned char *) &pack->timestamp, 16, (unsigned char *) &dec_pack->timestamp, key, iv);

    SHA256_Init(sha256_ctx);
    SHA256_Update(sha256_ctx, password, strlen(password));
    SHA256_Update(sha256_ctx, &dec_pack->timestamp, 8);
    SHA256_Update(sha256_ctx, dec_pack->noise, 8);
    SHA256_Final(md, sha256_ctx);

    if (memcmp(dec_pack->token, md, 16)) {
        logger(ERR, stdout, "token error");
        exit(1);
    }
    if (check_replay(dec_pack->timestamp, dec_pack->noise)) {
        //packed may be replay, abort it
        logger(ERR, stdout, "replay packed");
        exit(1);
    }
    read_size(fd, &pack->main_version, 48);
    aes_dec(&pack->main_version, 48, &dec_pack->main_version, key, iv);
    if (dec_pack->main_version != 1) {
        logger(ERR, stdout, "unknown main version");
        exit(1);
    }
    data_size = dec_pack->length - dec_pack->random_len - 80;
    enc_data = malloc(data_size); 
    read_size(fd, enc_data, data_size);
    if (data_size + ctx->data_size > ctx->buffer_size) {
        ctx->buffer = realloc(ctx->buffer, data_size + ctx->data_size + BLCOK_SIZE);
        ctx->buffer_size = data_size + ctx->data_size + BLCOK_SIZE;
    }

    aes_dec(enc_data, data_size, ctx->buffer + ctx->data_size, key, iv);

    SHA256_Init(sha256_ctx);
    memcpy(md, dec_pack->hash_sum, 32);
    memset(dec_pack->hash_sum, 0, 32); // clean hash sum
    SHA256_Update(sha256_ctx, dec_pack, 80);
    memcpy(dec_pack->hash_sum, md, 32); // restore
    SHA256_Update(sha256_ctx, ctx->buffer + ctx->data_size, data_size);


    pad = *(ctx->buffer + ctx->data_size + data_size - 1);
    if (pad > 16) {     // BUG: no padding check
        logger(ERR, stdout, "unknown padding");
        exit(1);
    }
//    memset(ctx->buffer + ctx->data_size + data_size - pad, 0, pad);
    ctx->data_size += data_size - pad;
    free(enc_data);
    rand_data = alloca((int)(char)dec_pack->random_len); //dec_pack->random_len -> (int)(char)dec_pack->random_len for stackoverflow
    read_size(fd, rand_data, dec_pack->random_len);
    SHA256_Update(sha256_ctx, rand_data, dec_pack->random_len);

    // free(rand_data);

    SHA256_Final(md, sha256_ctx);


    if (memcmp(dec_pack->hash_sum, md, 32)) {
        logger(ERR, stdout, "hash sum mismatch");
        exit(1);
    }
}

void read_size_sc(sc_ctx *ctx, unsigned char *buffer, unsigned int size) {
    while (1) {
        if (ctx->data_size >= size) {
            memcpy(buffer, ctx->buffer, size);
            ctx->data_size -= size;
            memmove(ctx->buffer, ctx->buffer + size, ctx->data_size);
            if (ctx->data_size < ctx->buffer_size - BLCOK_SIZE) {
                ctx->buffer = realloc(ctx->buffer, ctx->data_size + BLCOK_SIZE);
                ctx->buffer_size = ctx->data_size + BLCOK_SIZE;
            }
            return;
        } else {
            read_sc_pack(ctx);
        }
    }
}