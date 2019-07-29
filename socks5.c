//
// Created by explorer on 7/18/19.
//

#include "socks5.h"
#include <unistd.h>
#include <stdlib.h>
#include "unit.h"
#include "netio.h"
#include <netinet/in.h>
#include <string.h>
#include <netdb.h>
#include <errno.h>
#include "log.h"
#include "sc.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>


void method_select_err(int fd) {
    unsigned char out_buf[2];
    // method not find
    struct sockaddr_in addr;
    unsigned int addr_len;
    addr_len = sizeof(addr);

    getpeername(fd, (struct sockaddr *) &addr, (socklen_t *) &addr_len);
    logger(ERR, stderr, "socks5 method err %s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));


    out_buf[0] = 5;
    out_buf[1] = 0xff;
    write(fd, out_buf, 2);
    close(fd);
    exit(0);
}

void resp_err(int fd, unsigned char err_code, in_addr_t ip, in_port_t port) {
    unsigned char buf[10];

    struct sockaddr_in addr;
    unsigned int addr_len;
    addr_len = sizeof(addr);

    getpeername(fd, (struct sockaddr *) &addr, (socklen_t *) &addr_len);
    logger(ERR, stderr, "socks5 conn error from %s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));


    buf[0] = 5;
    buf[1] = err_code;
    buf[2] = 0;
    buf[3] = 1;
    memcpy(buf + 4, &ip, 4);
    memcpy(buf + 8, &port, 2);
    write(fd, buf, 10);
    close(fd);
    exit(0);
}

int socks5_server(int fd) {
    unsigned char in_buffer[0x100];
    unsigned char out_buf[0x100];
    unsigned int i, method_count, addr_len;
    unsigned char url_size = 0, err_code;
    struct hostent *host;
    int addr_type;
    struct sockaddr_in addr;
    in_addr_t ip, s_ip;
    in_port_t port, s_port;
    int client_fd, result;
    char *url = 0;


    // get methods
    read_size(fd, in_buffer, 2);
    if (in_buffer[0] != 5) {
        // not a socks5
        getpeername(fd, (struct sockaddr *) &addr, (socklen_t *) &addr_len);
        logger(ERR, stderr, "get a no socks5 conn from %s:%d", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        close(fd);
        exit(0);
    }
    if (in_buffer[1] < 1) {
        // no method?
        method_select_err(fd);
    }
    method_count = in_buffer[1];
    read_size(fd, in_buffer, method_count);
    for (i = 0; i < method_count; i++) {
        if (in_buffer[i] == 0) {
            break;
        }
    }
    if (i == method_count) {
        // method not find
        method_select_err(fd);
    }
    out_buf[0] = 5;
    out_buf[1] = 0;
    write(fd, out_buf, 2);

    // get req
    read_size(fd, in_buffer, 4);
    if (in_buffer[0] != 5 || in_buffer[2] != 0) {
        resp_err(fd, 1, 0, 0);
    }
    if (in_buffer[1] != 1) {
        resp_err(fd, 7, 0, 0);
    }

    addr_type = in_buffer[3];
    if (addr_type == 1) {
        read_size(fd, (unsigned char *) &ip, 4);
        read_size(fd, (unsigned char *) &port, 2);
    } else if (addr_type == 3) {
        read_size(fd, &url_size, 1);
        url = malloc(url_size + 1);
        memset(url, 0, url_size + 1);
        read_size(fd, (unsigned char *) url, url_size);
        read_size(fd, (unsigned char *) &port, 2);
    } else {
        resp_err(fd, 8, 0, 0);
    }
//    if (addr_type == 3) {
//        host = gethostbyname(url);
//        if (host == NULL || host->h_addrtype == AF_INET6) {
//            // host lookup error
//            resp_err(fd, 8, 0, 0);
//        }
//        memcpy(&ip, host->h_addr, 4);
//    }

    if (addr_type == 1) {
        struct in_addr tmp;
        tmp.s_addr = ip;
        logger(INFO, stderr, "get  socks5 req to %s:%d", inet_ntoa(tmp), ntohs(port));
    } else {
        logger(INFO, stderr, "get  socks5 req to %s:%d", url, ntohs(port));
    }


//    client_fd = tcp_conn(ip, port);
    if (addr_type == 1) {
        client_fd = sc_client(addr_type, (unsigned char *) &ip, 4, port);
    } else {
        client_fd = sc_client(addr_type, (unsigned char *) url, url_size, port);
    }

    if (client_fd == -2) {
        resp_err(fd, 1, 0, 0);
        logger(ERR, stderr, "conn error %s", strerror(errno));
    } else if (client_fd == -1) {
        if (errno == ENETUNREACH) {
            err_code = 3;
        } else if (errno == ECONNREFUSED) {
            err_code = 5;
        } else {
            err_code = 0xff;
        }
        logger(ERR, stderr, "conn error %s", strerror(errno));
        resp_err(fd, err_code, 0, 0);
    }

    addr_len = sizeof(addr);
    result = getsockname(fd, (struct sockaddr *) &addr, (socklen_t *) &addr_len);
    if (result == -1) {
        logger(ERR, stderr, "error on get peer name");
        resp_err(fd, 0xff, 0, 0);
    }

    s_ip = addr.sin_addr.s_addr;
    s_port = addr.sin_port;

    out_buf[0] = 5;
    out_buf[1] = 0;
    out_buf[2] = 0;
    out_buf[3] = 1;
    memcpy(out_buf + 4, &s_ip, 4);
    memcpy(out_buf + 8, &s_port, 2);
    write(fd, out_buf, 10);
    return client_fd;
    // the connection is success, start transport
}