#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <gmp.h>

#include "gmp_helper.h"

/**
 * urandom_read() - read /dev/urandom
 *
 * @return  random uint64
 */
uint64_t urandom_read(void)
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
 * __mpz_uranodmb() - wrap of mpz_urandomb()
 *
 * get rid of init gmp_randstate_t
 * randomly in the range 0 to (2^n)-1, inclusive
 *
 * @param   rop: randomly result to store
 * @param   n: binary length
 */
void __mpz_urandomb(mpz_t rop, mp_bitcnt_t n)
{
        gmp_randstate_t rstate;

        gmp_randinit_mt(rstate);
        gmp_randseed_ui(rstate, urandom_read());

        mpz_urandomb(rop, rstate, n);

        gmp_randclear(rstate);
}

/**
 * __mpz_uranodmm() - wrap of mpz_urandomm()
 *
 * get rid of init gmp_randstate_t
 * randomly in the range 0 to (n - 1), inclusive
 *
 * @param   rop: randomly result to store
 * @param   n: max number
 */
void __mpz_urandomm(mpz_t rop, const mpz_t n)
{
        gmp_randstate_t rstate;

        gmp_randinit_mt(rstate);
        gmp_randseed_ui(rstate, urandom_read());

        mpz_urandomm(rop, rstate, n);

        gmp_randclear(rstate);
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
        mpz_t upper;    /* not used */
        mpz_t lower;

        if (len < 1)
                return -EINVAL;

        mpz_inits(res, upper, lower, NULL);

        mpz_set_ui(upper, 1);
        mpz_set_ui(lower, 1);

        mpz_mul_2exp(upper, upper, len);
        mpz_mul_2exp(lower, lower, len - 1);

        while (1) {
                /* return random number below (2^n) - 1*/
                __mpz_urandomb(res, len);

                if (mpz_cmp(res, lower) >= 0) {
                        break;
                }
        }

        /* rop must not null */
        mpz_set(rop, res);

        mpz_clears(res, upper, lower, NULL);

        return 0;
}

/**
 * mpz_check_binlen() - verify the number binary length
 *
 * @param   src: number to verify
 * @param   len: binary length to check
 * @return  0 on proper length, others on failure
 */
int mpz_check_binlen(const mpz_t src, uint64_t len)
{
        mpz_t t;
        int res;

        mpz_inits(t, NULL);

        mpz_div_2exp(t, src, len - 1);

        /*
         * Larger than 1 also does not fit
         */
        if (mpz_get_ui(t) == 1)
                res = 0;
        else
                res = 1;

        mpz_clears(t, NULL);

        return res;
}