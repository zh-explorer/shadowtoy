//
// Created by explorer on 7/18/19.
//

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
#include "log.h"

int tcp_listen(in_addr_t ip, in_port_t port) {
    struct sockaddr_in serv_addr;
    int server_fd;


    server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd == 1) {
        logger(ERR, stderr, "socket create: %s", strerror(errno));
        exit(1);
    }

    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_addr.s_addr = ip;
    serv_addr.sin_port = port;

    // let system give us port
//    if (bind(server_fd, (const struct sockaddr *) &serv_addr, sizeof(serv_addr)) == -1) {
//        logger(ERR, stderr, "bind: %s", strerror(errno));
//        exit(1);
//    }

    if (listen(server_fd, 30) == -1) {
        logger(ERR, stderr, "listen: %s", strerror(errno));
        exit(1);
    }
    return server_fd;
}

int tcp_conn(in_addr_t ip, in_port_t port) {
    struct sockaddr_in client_addr;
    int client_fd;
    client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd == 1) {
        return -2;
    }

    memset(&client_addr, 0, sizeof(client_addr));
    client_addr.sin_family = AF_INET;
    client_addr.sin_addr.s_addr = ip;
    client_addr.sin_port = port;

    if (connect(client_fd, (const struct sockaddr *) &client_addr, sizeof(client_addr)) < 0) {
        return -1;
    }

    return client_fd;
}