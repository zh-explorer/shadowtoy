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
#include <wait.h>
#include "poll.h"
#include <signal.h>
#include "unit.h"
#include <sys/select.h>

#define LISTEN_IP "0.0.0.0"
#define LISTEN_PORT 13343

int main(int argc, char *argv[]) {
    int server_fd;
    int accpet_fd;
    int client_fd;
    pid_t pid;
    in_addr_t ip;
    int port;
    struct sockaddr_in addr;
    unsigned int addr_len;
    int result;
    fd_set fdSet;
    char *buffer[1024];

//    signal(SIGHUP, handle);
//    signal(SIGPIPE, handle);

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

    addr_len = sizeof(addr);
    result = getsockname(server_fd, (struct sockaddr *) &addr, (socklen_t *) &addr_len);
    if (result == -1) {
        puts("can not find port, maybe server is error");
    }
    printf("now you server if at %d port\n", ntohs(addr.sin_port));
    fflush(stdout);

    FD_ZERO(&fdSet);
    FD_SET(STDIN_FILENO, &fdSet);
    FD_SET(server_fd, &fdSet);
    set_noblock(server_fd);
    set_noblock(STDIN_FILENO);

    while (1) {
        FD_ZERO(&fdSet);
        FD_SET(STDIN_FILENO, &fdSet);
        FD_SET(server_fd, &fdSet);

        result = select(4, &fdSet, NULL, NULL, 0);

        if (FD_ISSET(server_fd, &fdSet)) {
            accpet_fd = accept(server_fd, NULL, NULL);
            if (accpet_fd < 0) {
                // skip this connection
                logger(ERR, stderr, "get a err fd", strerror(errno));
                continue;
            }
//            sleep(1);  //Prevent brute force
            pid = fork();
            if (pid == -1) {
                logger(ERR, stderr, "fork error", strerror(errno));
                // fork error
                exit(1);
            }
            if (pid != 0) {
                // parent
                close(accpet_fd);
                wait(NULL);
            } else {
                pid = fork();
                if (pid == -1) {
                    logger(ERR, stderr, "fork error", strerror(errno));
                    // fork error
                    exit(1);
                } else if (pid != 0) {
                    // parent
                    exit(0);
                }
                break;
            }
        }
        if (FD_ISSET(STDIN_FILENO, &fdSet)) {
            result = read(STDIN_FILENO, buffer, 1024);
            if (result <= 0) {
                exit(0);
            }
        }
    }
    //only child can get here
    client_fd = sc_server(accpet_fd);
    sc_transport(accpet_fd, client_fd);
}