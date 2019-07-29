//
// Created by explorer on 7/18/19.
//

#ifndef SHDOWTOY_NETIO_H
#define SHDOWTOY_NETIO_H


#include <netinet/in.h>

int tcp_conn(in_addr_t ip, in_port_t port);

int tcp_listen(in_addr_t ip, in_port_t port);

#endif //SHDOWTOY_NETIO_H
