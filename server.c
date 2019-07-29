//
// Created by explorer on 7/19/19.
//
#include <stdio.h>
#include "netio.h"
#include "log.h"
#include "sc.h"
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdlib.h>
#include "poll.h"


#define LISTEN_IP "0.0.0.0"
#define LISTEN_PORT 8888

int main(int argc, char *argv[]) {
    int server_fd;
    int accpet_fd;
    int client_fd;
    pid_t pid;
    in_addr_t ip;
    int port;

    if (argc == 2) {
        port = atoi(argv[1]);
        if (port < 0 || port > 0xffff) {
            port = LISTEN_PORT;
        }
    } else {
        port = LISTEN_PORT;
    }

    ip = inet_addr(LISTEN_IP);
    server_fd = tcp_listen(ip, htons(port));

    while (1) {
        accpet_fd = accept(server_fd, NULL, NULL);
        if (accpet_fd < 0) {
            // skip this connection
            logger(ERR, stderr, "get a err fd", strerror(errno));
            continue;
        }
        pid = fork();
        if (pid == -1) {
            logger(ERR, stderr, "fork error", strerror(errno));
            // fork error
            exit(1);
        }
        if (pid != 0) {
            // parent
            close(accpet_fd);
        } else {
            break;
        }
    }
    //only child can get here
    client_fd = sc_server(accpet_fd);
    sc_transport(accpet_fd, client_fd);
}