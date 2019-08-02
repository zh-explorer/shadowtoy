//
// Created by explorer on 8/1/19.
//

#include "modpow.h"
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

uint64_t GCD(int64_t a, int64_t b) {
    int64_t i;
    int64_t x = 0, y = 1;
    int64_t n = b;
    while (b) {
        i = x;
        x = y - x * (a / b);
        y = i;
        i = b;
        b = a % b;
        a = i;
    }
    return (uint64_t) y % n;
}

//  a*b/n
big_integer *montgomery(big_integer *a, big_integer *b, big_integer *n) {
    big_integer *r = create_integer();
    big_integer *newN, *newA;
    uint32_t m = 0x100000000 - GCD(get_low(n), 0x100000000);
    integer_node *p;
    uint32_t q;
    int number, i;

    if (b->size < n->size) {
        number = n->size - b->size;
        for (i = 0; i < number; i++) {
            add_new_to_tail(b, 0);
        }
    }

    for (p = b->head; p; p = p->next) {
        q = (get_low(r) + p->num * get_low(a)) * m;

        // r = r + b[i]*a + q*N
        newA = integer_copy(a);
        mul_num(newA, p->num);
        newN = integer_copy(n);
        mul_num(newN, q);
        add_integer(r, newA);
        add_integer(r, newN);

        delete_integer(newA);
        delete_integer(newN);

        // r = r/0x100000000
        del_head(r);
    }

    if (num_cmp(r, n) == 1) {
        sub_integer(r, n);
    }
    return r;
}

big_integer *createR(big_integer *n) {
    big_integer *r = create_integer();
    int i;
    int times = n->size * 32 * 2;
    add_num(r, 1);

    for (i = 0; i < times; i++) {
        mul_num(r, 2);
        if (num_cmp(r, n) == 1) {
            sub_integer(r, n);
        }
    }
    return r;
}

big_integer *mod_pow(big_integer *x, big_integer *y, big_integer *n) {
    big_integer *one = create_integer();
    big_integer *r = createR(n);
    big_integer *mon_t, *mon_x, *new_mon_t;
    integer_node *p;
    int i, bit;

    add_num(one, 1);
    mon_t = montgomery(one, r, n);
//    delete_integer(one);
    mon_x = montgomery(x, r, n);
    delete_integer(r);

    for (p = y->tail; p; p = p->prev) {
        for (i = 31; i >= 0; i--) {
            new_mon_t = montgomery(mon_t, mon_t, n);
            delete_integer(mon_t);
            mon_t = new_mon_t;

            bit = p->num >> i;
            if (bit & 1) {
                new_mon_t = montgomery(mon_t, mon_x, n);
                delete_integer(mon_t);
                mon_t = new_mon_t;
            }
        }
    }

    delete_integer(mon_x);
    new_mon_t = montgomery(mon_t, one, n);
    delete_integer(one);
    delete_integer(mon_t);
    return new_mon_t;
}
