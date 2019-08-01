//
// Created by explorer on 7/18/19.
//

#include "poll.h"

#include <sys/socket.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/stat.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "unit.h"
#include "sc.h"
#include "log.h"
#include <openssl/sha.h>

#define BLCOK_SIZE 0x100

typedef struct {
    int fd;
    unsigned char *buffer;
    unsigned int size;
} fd_ctx;

void direct_transport(int fd1, int fd2) {
    int poll_fd = epoll_create(20);
    int re, i;
    unsigned char *data;
    unsigned int result;
    unsigned int recv_size, send_size, size;
    fd_ctx ctx[2];
    fd_ctx *c, *o;
    struct epoll_event events[2], tmp;
    struct epoll_event *p = &events[0];

    memset(ctx, 0, sizeof(fd_ctx) * 2);
    ctx[0].fd = fd1;
    ctx[1].fd = fd2;

    set_noblock(fd1);
    set_noblock(fd2);

    p->events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    p->data.fd = fd1;
    epoll_ctl(poll_fd, EPOLL_CTL_ADD, fd1, p);

    p->events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    p->data.fd = fd2;
    epoll_ctl(poll_fd, EPOLL_CTL_ADD, fd2, p);

    while (1) {
        re = epoll_wait(poll_fd, events, 2, -1);
        for (i = 0; i < re; i++) {
            p = &events[i];
            if (p->data.fd == ctx[0].fd) {
                c = &ctx[0];
                o = &ctx[1];
            } else {
                c = &ctx[1];
                o = &ctx[0];
            }
            if (p->events & EPOLLIN) {
                recv_size = c->size;
                data = c->buffer;
                while (1) {
                    data = realloc(data, recv_size + BLCOK_SIZE);
                    result = (unsigned int) read(c->fd, data + recv_size, BLCOK_SIZE);
                    if (result == 0 || (result == -1 && errno == EAGAIN)) {
                        send_size = 0;
                        while (send_size != recv_size) {
                            result = (unsigned int) write(o->fd, data + send_size, recv_size - send_size);
                            if (result == -1) {
                                if (errno == EAGAIN) {
                                    // write for epoll
                                    c->buffer = malloc(recv_size - send_size);
                                    memcpy(c->buffer, data + send_size, recv_size - send_size);
                                    c->size = recv_size - send_size;
                                    tmp.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLOUT;
                                    tmp.data.fd = o->fd;
                                    epoll_ctl(poll_fd, EPOLL_CTL_MOD, o->fd, &tmp);
                                }
                                // write error
                                close(fd1);
                                close(fd2);
                                exit(0);
                            }
                            send_size += result;
                        }
                        free(data);
                        if (send_size == recv_size) {
                            c->buffer = 0;
                            c->size = 0;
                        }
                        break;
                    }
                    if (result == -1) {
                        // get error, close;
                        close(fd1);
                        close(fd2);
                        exit(0);
                    }
                    recv_size += result;
                }

            }
            if (p->events & EPOLLOUT) {
                send_size = 0;
                size = o->size;
                data = o->buffer;
                while (send_size != size) {
                    result = (unsigned int) write(c->fd, data + send_size, size - send_size);
                    if (result == -1) {
                        if (errno == EAGAIN) {
                            // write for epoll
                            o->buffer = malloc(size - send_size);
                            memcpy(c->buffer, data + send_size, size - send_size);
                            o->size = size - send_size;
                            tmp.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLOUT;
                            tmp.data.fd = o->fd;
                            epoll_ctl(poll_fd, EPOLL_CTL_MOD, o->fd, &tmp);
                        }
                        // write error
                        close(fd1);
                        close(fd2);
                        exit(0);
                    }
                    send_size += result;
                }
                free(data);
                if (send_size == size) {
                    o->buffer = 0;
                    o->size = 0;
                }
            }
            if (p->events & EPOLLERR || p->events & EPOLLHUP || p->events & EPOLLRDHUP) {
                // err close
                close(fd1);
                close(fd2);
                exit(0);
            }
        }
    }
}

typedef enum {
    start,
    read_head,
    read_data,
    read_rand,
} sc_status;
unsigned char *sc_data;
unsigned int sc_size;
sc_status status = start;
sc_package pack;
sc_package dec_pack;
unsigned char key[16];
unsigned char iv[16];

void sc_transport(int fd1, int fd2) {
    int poll_fd = epoll_create(20);
    int re, i;
    unsigned char *data, *enc_data;
    unsigned int result;
    SHA256_CTX sha256_ctx;
    unsigned char md[16];
    char pad;
    unsigned int recv_size, send_size, size, data_size, enc_data_size;
    fd_ctx ctx[2];
    fd_ctx *c, *o;
    struct epoll_event events[2], tmp;
    struct epoll_event *p = &events[0];

    memset(ctx, 0, sizeof(fd_ctx) * 2);
    ctx[0].fd = fd1;
    ctx[1].fd = fd2;

    set_noblock(fd1);
    set_noblock(fd2);

    p->events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    p->data.fd = fd1;
    epoll_ctl(poll_fd, EPOLL_CTL_ADD, fd1, p);

    p->events = EPOLLIN | EPOLLET | EPOLLRDHUP;
    p->data.fd = fd2;
    epoll_ctl(poll_fd, EPOLL_CTL_ADD, fd2, p);

    while (1) {
        re = epoll_wait(poll_fd, events, 2, -1);
        for (i = 0; i < re; i++) {
            p = &events[i];
            if (p->data.fd == ctx[0].fd) {
                c = &ctx[0];
                o = &ctx[1];
            } else {
                c = &ctx[1];
                o = &ctx[0];
            }
            if (p->events & EPOLLIN) {
                if (c->fd == fd1) {
                    data = sc_data;
                    recv_size = sc_size;
                    while (1) {
                        data = realloc(data, recv_size + BLCOK_SIZE);
                        result = (unsigned int) read(c->fd, data + recv_size, BLCOK_SIZE);
                        if (result == 0 || (result == -1 && errno == EAGAIN)) {
                            break;
                        }
                        recv_size += result;
                    }
                    sc_data = data;
                    sc_size = recv_size;
                    read_start:
                    if (status == start) {
                        if (sc_size >= 32) {
                            memcpy(dec_pack.token, sc_data, 16);
                            SHA256_Init(&sha256_ctx);
                            SHA256_Update(&sha256_ctx, password, strlen(password));
                            SHA256_Update(&sha256_ctx, dec_pack.token, 16);
                            SHA256_Final(md, &sha256_ctx);
                            memcpy(key, md, 16);
                            memcpy(iv, md + 16, 16);
                            memcpy(&pack.timestamp, sc_data + 16, 16);
                            aes_dec((unsigned char *) &pack.timestamp, 16, (unsigned char *) &dec_pack.timestamp, key,
                                    iv);

                            SHA256_Init(&sha256_ctx);
                            SHA256_Update(&sha256_ctx, password, strlen(password));
                            SHA256_Update(&sha256_ctx, &dec_pack.timestamp, 8);
                            SHA256_Update(&sha256_ctx, dec_pack.noise, 8);
                            SHA256_Final(md, &sha256_ctx);
                            if (memcmp(dec_pack.token, md, 16)) {
                                logger(ERR, stdout, "token error");
                                exit(1);
                            }

                            if (check_replay(dec_pack.timestamp, dec_pack.noise)) {
                                //packed may be replay, abort it
                                logger(ERR, stdout, "replay packed");
                                exit(1);
                            }
                            sc_size -= 32;
                            memmove(sc_data, sc_data + 32, sc_size);
                            status = read_head;
                        }
                    }
                    if (status == read_head) {
                        if (sc_size >= 48) {
                            memcpy(&pack.main_version, sc_data, 48);
                            aes_dec(&pack.main_version, 48, &dec_pack.main_version, key, iv);
                            if (dec_pack.main_version != 1) {
                                logger(ERR, stdout, "unknown main version");
                                exit(1);
                            }
                            sc_size -= 48;
                            memmove(sc_data, sc_data + 48, sc_size);
                            status = read_data;
                            SHA256_Init(&sha256_ctx);

                            memcpy(md, dec_pack.hash_sum, 32);
                            memset(dec_pack.hash_sum, 0, 32); // clean hash sum
                            SHA256_Update(&sha256_ctx, &dec_pack, 80);
                            memcpy(dec_pack.hash_sum, md, 32); // restore
                        }
                    }
                    if (status == read_data) {
                        if (sc_size >= dec_pack.length - dec_pack.random_len - 80) {
                            data_size = dec_pack.length - dec_pack.random_len - 80;
                            data = malloc(data_size);
                            aes_dec(sc_data, data_size, data, key, iv);
                            SHA256_Update(&sha256_ctx, data, data_size);

                            pad = data[data_size - 1]; // if pad < 0
                            if (pad > 16) {
                                logger(ERR, stdout, "unknown padding");
                                exit(1);
                            }

                            sc_size -= data_size;
                            memmove(sc_data, sc_data + data_size, sc_size);
                            status = read_rand;

                            data_size -= pad;
                            c->buffer = realloc(c->buffer, c->size + data_size); // c->buffer maybe have data
                            memcpy(c->buffer + c->size, data, data_size);
                            c->size += data_size;

                            free(data);
                        }
                    }
                    if (status == read_rand) {
                        if (sc_size >= dec_pack.random_len) {
                            SHA256_Update(&sha256_ctx, sc_data, dec_pack.random_len);
                            SHA256_Final(md, &sha256_ctx);
                            if (memcmp(dec_pack.hash_sum, md, 32)) {
                                logger(ERR, stdout, "hash sum mismatch");
                                exit(1);
                            }

                            sc_size -= dec_pack.random_len;
                            memmove(sc_data, sc_data + dec_pack.random_len, sc_size);
                            status = start;

                            // clean all
                            memset(&dec_pack, 0, sizeof(sc_package));
                            memset(&pack, 0, sizeof(sc_package));
                            memset(key, 0, 16);
                            memset(iv, 0, 16);
                            goto read_start;
                        }
                    }
                }

                // targe -> server
                if (c->fd == fd2) {
                    data = NULL;
                    recv_size = 0;
                    while (1) {
                        data = realloc(data, recv_size + BLCOK_SIZE);
                        result = (unsigned int) read(c->fd, data + recv_size, BLCOK_SIZE);
                        if (result == 0 || (result == -1 && errno == EAGAIN)) {
                            break;
                        }
                        recv_size += result;
                    }
                    enc_packet(data, recv_size, &enc_data, &enc_data_size);
                    free(data);
                    c->buffer = realloc(c->buffer, c->size + enc_data_size);
                    memcpy(c->buffer + c->size, enc_data, enc_data_size);
                    c->size += enc_data_size;
                    free(enc_data);
                }


                recv_size = c->size;
                data = c->buffer;
                send_size = 0;
                while (send_size != recv_size) {
                    result = (unsigned int) write(o->fd, data + send_size, recv_size - send_size);
                    if (result == -1) {
                        if (errno == EAGAIN) {
                            // write for epoll
                            c->buffer = malloc(recv_size - send_size);
                            memcpy(c->buffer, data + send_size, recv_size - send_size);
                            c->size = recv_size - send_size;
                            tmp.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLOUT;
                            tmp.data.fd = o->fd;
                            epoll_ctl(poll_fd, EPOLL_CTL_MOD, o->fd, &tmp);
                        }
                        // write error
                        close(fd1);
                        close(fd2);
                        exit(0);
                    }
                    send_size += result;
                }
                free(data);
                if (send_size == recv_size) {
                    c->buffer = 0;
                    c->size = 0;
                }
            }


            if (p->events & EPOLLOUT) {
                send_size = 0;
                size = o->size;
                data = o->buffer;
                while (send_size != size) {
                    result = (unsigned int) write(c->fd, data + send_size, size - send_size);
                    if (result == -1) {
                        if (errno == EAGAIN) {
                            // write for epoll
                            o->buffer = malloc(size - send_size);
                            memcpy(c->buffer, data + send_size, size - send_size);
                            o->size = size - send_size;
                            tmp.events = EPOLLIN | EPOLLET | EPOLLRDHUP | EPOLLOUT;
                            tmp.data.fd = o->fd;
                            epoll_ctl(poll_fd, EPOLL_CTL_MOD, o->fd, &tmp);
                        }
                        // write error
                        close(fd1);
                        close(fd2);
                        exit(0);
                    }
                    send_size += result;
                }
                free(data);
                if (send_size == size) {
                    o->buffer = 0;
                    o->size = 0;
                }
            }
            if (p->events & EPOLLERR || p->events & EPOLLHUP || p->events & EPOLLRDHUP) {
                // err close
                close(fd1);
                close(fd2);
                exit(0);
            }
        }
    }
}