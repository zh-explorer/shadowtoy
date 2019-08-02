//
// Created by explorer on 7/29/19.
//

#ifndef SHADOWTOY_NUM_CALC_H
#define SHADOWTOY_NUM_CALC_H
#define NUM_DEBUG

#include <stdint.h>

typedef struct integer_node integer_node;

typedef struct big_integer big_integer;

struct integer_node {
    struct integer_node *prev;
    struct integer_node *next;
    uint32_t num;
};

struct big_integer {
    struct integer_node *head;
    struct integer_node *tail;
//    struct integer_node *p;
    int size;

    // cache the last delete chunk for next use
    // this will reduce and simple the carry calc
    struct integer_node *cache;
};

#define get_low(integer) (integer)->head->num

struct integer_node *new_integer_node(struct big_integer *integer, uint32_t num);

struct big_integer *create_integer();

void delete_integer(struct big_integer *integer);

void add_new_to_tail(struct big_integer *integer, uint32_t num);

void clean_tail(struct big_integer *integer);

void del_head(struct big_integer *integer);

void add_num(struct big_integer *integer, uint32_t num);

void sub_num(struct big_integer *integer, uint32_t num);

void add_integer(struct big_integer *integer1, struct big_integer *integer2);

void sub_integer(struct big_integer *integer1, struct big_integer *integer2);

void mul_num(struct big_integer *integer, uint32_t num);

struct big_integer *integer_copy(struct big_integer *integer);

int num_cmp(struct big_integer *integer1, struct big_integer *integer2);

#ifdef NUM_DEBUG

void print_hex_num(struct big_integer *integer);

struct big_integer *from_str(char *str);

void print_array(struct big_integer *integer);

#endif

struct big_integer *from_array(const uint32_t *num, int size);

#endif //SHADOWTOY_NUM_CALC_H
