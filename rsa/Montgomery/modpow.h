//
// Created by explorer on 8/1/19.
//

#ifndef SHADOWTOY_MODPOW_H
#define SHADOWTOY_MODPOW_H

#include <stdint.h>
#include "../big_num/num_calc.h"

uint64_t GCD(int64_t a, int64_t b);

big_integer *mod_pow(big_integer *x, big_integer *y, big_integer *n);

#endif //SHADOWTOY_MODPOW_H
