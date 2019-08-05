//
// Created by explorer on 7/29/19.
//

#include <stdint.h>
#include "num_calc.h"
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdio.h>

#define  likely(x)        __builtin_expect(!!(x), 1)
#define  unlikely(x)      __builtin_expect(!!(x), 0)

struct integer_node *new_integer_node(struct big_integer *integer, uint32_t num) {
    struct integer_node *p;

    // if we have a cache chunk, use it
    if (integer->cache) {
        p = integer->cache;
        integer->cache = NULL;
    } else {
        p = malloc(sizeof(struct integer_node));
    }
    memset(p, 0, sizeof(struct integer_node));
    p->num = num;
    return p;
}

struct big_integer *create_integer() {
    struct big_integer *p;
    p = malloc(sizeof(struct big_integer));
    memset(p, 0, sizeof(struct big_integer));
    p->head = new_integer_node(p, 0);
    p->tail = p->head;
    p->size = 1;
    return p;
}

void delete_integer(struct big_integer *integer) {
    struct integer_node *tmp, *prev;
    if (integer->cache) {
        free(integer->cache);
    }
    for (tmp = integer->head, prev = NULL; tmp; tmp = tmp->next) {
        free(prev);
        prev = tmp;
    }
    free(prev);
}

//void seek_head(struct big_integer *integer) {
//    integer->p = integer->head;
//}
//
//void seek_tail(struct big_integer *integer) {
//    integer->p = integer->tail;
//}

void add_new_to_tail(struct big_integer *integer, uint32_t num) {
    struct integer_node *new = new_integer_node(integer, num);
    new->next = NULL;
    new->prev = integer->tail;

    integer->tail->next = new;
    integer->size += 1;
    integer->tail = new;
}

// delete the tail zero block of integer after sub.
void clean_tail(struct big_integer *integer) {
    struct integer_node *tmp;
    tmp = integer->tail;
    while (tmp->num == 0) {
        if (unlikely(tmp->prev == NULL)) {
            // do not free the last node
            break;
        }
        tmp = tmp->prev;
        // we cache a chunk
        if (integer->cache) {
            free(tmp->next);
        } else {
            integer->cache = tmp->next;
        }
        integer->size -= 1;
    }
    // set tmp->next and integer->tail is not necessary in loop
    tmp->next = NULL;
    integer->tail = tmp;
}

void del_head(struct big_integer *integer) {
    struct integer_node *p = integer->head;
    if (p->next == NULL) {  // do not del the last one
        p->num = 0;
        return;
    }
    integer->head = p->next;
    p->next->prev = NULL;
    free(p);
    integer->size -= 1;
}

// add a num to place of p and deal with carry
// make sure integer->p is set
// this function do not change p
//void add_num_to_p(struct big_integer *integer, uint32_t num) {
//    // if integer is null, add to tail
//    struct integer_node *tmp;
//    uint64_t reg;
//    if (integer->p == NULL) {
//        add_new_to_tail(integer, num);
//        return;
//    }
//    tmp = integer->p;
//    reg = tmp->num + num;
//    tmp->num = reg;
//    if (reg & 0x100000000) {
//        // deal with canary
//        tmp = tmp->next;
//        while (tmp && tmp->num == 0xffffffff) {
//            tmp->num = 0;
//            tmp = tmp->next;
//        }
//        if (tmp) {  // need a new node to store carry
//            add_new_to_tail(integer, 1);
//        }
//    }
//}

// add a 32bit num to integer
void add_num(struct big_integer *integer, uint32_t num) {
    struct integer_node *tmp;
    uint64_t reg;

    //first we add a new node to tail
    add_new_to_tail(integer, 0);

    tmp = integer->head;

    while (1) {
        reg = tmp->num;
        reg = reg + num;
        tmp->num = reg;
        if (likely((reg & 0x100000000) == 0)) {
            break;
        }
        // we add a new node, so next always not null
        tmp = tmp->next;
        num = 1;
    }
    clean_tail(integer);
}

// sub a 32bit num to integer
// make sure integer > num
void sub_num(struct big_integer *integer, uint32_t num) {
    struct integer_node *tmp;
    int64_t reg;

    tmp = integer->head;
    while (1) {
        reg = tmp->num;
        reg = reg - num;
        if (likely(reg >= 0)) {
            tmp->num = reg;
            break;
        } else {
            tmp->num = 0x100000000 + reg;
            tmp = tmp->next; // because integer great than num, tmp->next will not be null
            num = 1;
        }
    }
}

// add integer1 to integer2
void add_integer(struct big_integer *integer1, struct big_integer *integer2) {
    int i, carry;
    struct integer_node *p1, *p2;
    uint64_t reg;
    int number;
    // first, we make sure integer1's size great tha integer2 and have a zero tail node
    if (integer1->size >= integer2->size) {
        add_new_to_tail(integer1, 0);
    } else {
        number = (integer2->size - integer1->size) + 1;
        for (i = 0; i < number; i++) {
            add_new_to_tail(integer1, 0);
        }
    }

    carry = 0;
    for (p1 = integer1->head, p2 = integer2->head; p2; p1 = p1->next, p2 = p2->next) {
        // we spilt the add avoid integer overflow
        reg = p1->num;
        reg = reg + p2->num;
        reg = reg + carry;
        p1->num = reg;
        if (reg & 0x100000000) {
            carry = 1;
        } else {
            carry = 0;
        }
    }
    if (unlikely(carry)) {
        while ((unlikely(p1->num == 0xffffffff))) {
            p1->num = 0;
            p1 = p1->next;
        }
        p1->num += 1;
    }
    clean_tail(integer1);
}

// int1 = int1 - int2
// make sure the int1 > int2
void sub_integer(struct big_integer *integer1, struct big_integer *integer2) {
    struct integer_node *p1, *p2;
    int64_t reg, carry;

    carry = 0;
    for (p1 = integer1->head, p2 = integer2->head; p2; p1 = p1->next, p2 = p2->next) {
        reg = p1->num;
        reg = reg - p2->num;
        reg = reg - carry;
        if (reg >= 0) {
            carry = 0;
            p1->num = reg;
        } else {
            carry = 1;
            p1->num = 0x100000000 + reg;
        }
    }
    if (unlikely(carry)) {
        while (unlikely(p1->num == 0)) {
            p1->num = 0xffffffff;
            p1 = p1->next;
        }
        p1->num -= 1;
    }

    clean_tail(integer1);
}

//int = int * num
void mul_num(struct big_integer *integer, uint32_t num) {
    struct integer_node *tmp;
    uint64_t reg;
    uint32_t carry;
    add_new_to_tail(integer, 0);

    carry = 0;
    for (tmp = integer->head; tmp; tmp = tmp->next) {
        reg = tmp->num;
        reg = reg * num;
        reg = reg + carry;
        tmp->num = reg;
        carry = reg >> 32;
    }

    clean_tail(integer);
}

// create and deep copy a new integer
struct big_integer *integer_copy(struct big_integer *integer) {
    // do all thing by our self
    struct big_integer *new = malloc(sizeof(struct big_integer));
    struct integer_node *tmp, *p, *new_node;
    new->size = integer->size;

    p = malloc(sizeof(struct integer_node));
    new->head = p;
    p->prev = NULL;

    for (tmp = integer->head; tmp; tmp = tmp->next) {
        p->num = tmp->num;
        new_node = malloc(sizeof(struct integer_node));
        p->next = new_node;
        new_node->prev = p;
        p = new_node;
    }
    new->tail = p->prev;
    new->tail->next = NULL;
    new->cache = p;
    return new;
}

// int1 > int2 -> ret 1
// int1 == int2 -> ret 0
// int1 < int2 -> ret-1
int num_cmp(struct big_integer *integer1, struct big_integer *integer2) {
    struct integer_node *p1, *p2;
    if (integer1->size > integer2->size) {
        return 1;
    } else if (integer1->size < integer2->size) {
        return -1;
    }

    for (p1 = integer1->tail, p2 = integer2->tail; p1; p1 = p1->prev, p2 = p2->prev) {
        if (likely(p1->num != p2->num)) {
            break;
        }
    }
    if (!p1) {
        return 0;
    }
    if (p1->num > p2->num) {
        return 1;
    } else {
        return -1;
    }
}

#ifdef NUM_DEBUG
char *hex_table = "0123456789abcdef";

void print_hex_num(struct big_integer *integer) {
    struct integer_node *p;
    int i;
    int ch, flag = 0;
    p = integer->tail;
    for (i = 7; i >= 0; i--) {
        ch = p->num >> (4 * i);
        ch = ch & 0xf;
        if (ch == 0 && flag == 0) {
            continue;
        }
        flag = 1;
        putchar(hex_table[ch]);
    }

    p = p->prev;
    while (p) {
        for (i = 7; i >= 0; i--) {
            ch = p->num >> (4 * i);
            ch = ch & 0xf;
            putchar(hex_table[ch]);
        }
        p = p->prev;
    }
}

void print_array(struct big_integer *integer) {
    struct integer_node *p;
    for (p = integer->head; p; p = p->next) {
        printf("0x%x", p->num);
        if (p->next) {
            printf(", ");
        }
    }
}

struct big_integer *from_str(char *str) {
    unsigned long i;
    char ch;
    struct big_integer *new = create_integer();
    for (i = 0; i < strlen(str); i++) {
        ch = str[i];
        ch -= 0x30;
        mul_num(new, 10);
        add_num(new, ch);
    }
    return new;
}

#endif

struct big_integer *from_array(const uint32_t *num, int size) {
    struct big_integer *new = malloc(sizeof(struct big_integer));
    struct integer_node *p, *new_node;
    int i;

    new_node = malloc(sizeof(struct integer_node));
    new_node->prev = NULL;
    new->head = new_node;
    p = new_node;
    for (i = 0; i < size; i++) {
        p->num = num[i];
        new_node = malloc(sizeof(struct integer_node));
        p->next = new_node;
        new_node->prev = p;
        p = new_node;
    }

    p->prev->next = NULL;
    new->tail = p->prev;
    new->cache = p;
    new->size = size;
    return new;
}

struct big_integer *from_bytes(const unsigned char *bytes, unsigned int size) {
    struct big_integer *new = malloc(sizeof(struct big_integer));
    struct integer_node *p, *new_node;
    int i;
    uint32_t *num = (uint32_t * )bytes;

    new_node = malloc(sizeof(struct integer_node));
    new_node->prev = NULL;
    new->head = new_node;
    p = new_node;
    for (i = 0; i < (size / 4); i++) {
        p->num = num[i];
        new_node = malloc(sizeof(struct integer_node));
        p->next = new_node;
        new_node->prev = p;
        p = new_node;
    }
    if (size % 4 != 0) {
        p->next = NULL;
        new->cache = NULL;
        new->tail = p;
        p->num = 0;
        memcpy(&p->num, bytes + 4 * i, size % 4);
        new->size = size / 4 + 1;
    } else {
        p->prev->next = NULL;
        new->tail = p->prev;
        new->cache = p;
        new->size = size / 4;
    }
    return new;
}

void to_bytes(big_integer *integer, unsigned char **buf, unsigned int *size) {
    int i;
    integer_node *node;
    uint32_t *p = malloc(integer->size * 4);
    *size = integer->size * 4;
    for (i = 0, node = integer->head; i < integer->size; i++, node = node->next) {
        p[i] = node->num;
    }
    *buf = (unsigned char *)p;
}