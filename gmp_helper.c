#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <gmp.h>

#include "gmp_helper.h"
#include "rsa_digest.h"

/**
 * urandom_read() - read /dev/urandom
 *
 * @return  random uint64
 */
uint64_t urandom_read()
{
        FILE *dev;
        uint64_t res;

        dev = fopen("/dev/urandom", "r");
        if (!dev)
                return EIO;

        fread(&res, sizeof(uint64_t), 1, dev);

        fclose(dev);

        return res;
}

/**
 * mpz_rand_bitlen() - get random number at given binary length
 *
 * @param   rop: result to store
 * @param   len: binary length wanted
 * @return  0 on success
 */
int mpz_rand_bitlen(mpz_t rop, uint64_t len)
{
        mpz_t res;
        mpz_t rseed;
        mpz_t upper;    /* not used */
        mpz_t lower;
        gmp_randstate_t rstate;

        if (!rop)
                return -EINVAL;

        if (len < 1)
                return -EINVAL;

        mpz_inits(res, rseed, upper, lower, NULL);

        mpz_set_ui(upper, 1);
        mpz_set_ui(lower, 1);
        mpz_set_ui(rseed, urandom_read());

        mpz_mul_2exp(upper, upper, len);
        mpz_mul_2exp(lower, lower, len - 1);

        gmp_randinit_mt(rstate);
        gmp_randseed(rstate, rseed);

        while (1) {
                /* return random number below (2^n) - 1*/
                mpz_urandomb(res, rstate, len);

                if (mpz_cmp(res, lower) >= 0) {
                        break;
                }
        }

        mpz_set(rop, res);

        mpz_clears(res, rseed, upper, lower, NULL);
        gmp_randclear(rstate);

        return 0;
}