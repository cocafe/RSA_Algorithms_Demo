/**
 * ras_keygen.c - RSA key generation algorithm
 *
 *      Author: cocafe <cocafehj@gmail.com> 2016
 *
 * Reference: <https://tools.ietf.org/html/rfc2313>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include "rsa.h"

/**
 * rsa_key_init() - init gmp elements in key
 *
 * @param   key: pointer to key struct
 * @return
 */
int rsa_private_key_init(struct rsa_private *key)
{
        if (!key)
                return -EINVAL;

        memset(key, 0x00, sizeof(struct rsa_private));
        mpz_inits(key->n,
                   key->p,
                   key->q,
                   key->e,
                   key->d,
                   key->exp1,
                   key->exp2,
                   key->coeff,
                   NULL);

        return 0;
}

/**
 * rsa_key_clean() - free gmp elements in key
 *
 * @param   key: pointer to key struct
 * @return
 */
int rsa_private_key_clean(struct rsa_private *key)
{
        if (!key)
                return -EINVAL;

        memset(key, 0x00, sizeof(struct rsa_private));
        mpz_clears(key->n,
                   key->p,
                   key->q,
                   key->e,
                   key->d,
                   key->exp1,
                   key->exp2,
                   key->coeff,
                   NULL);

        return 0;
}

/**
 * rsa_public_key_init() - init gmp elements in key
 *
 * @param   key: pointer to key struct
 * @return
 */
int rsa_public_key_init(struct rsa_public *key)
{
        if (!key)
                return -EINVAL;

        mpz_inits(key->n, key->e, NULL);

        return 0;
}

/**
 * rsa_public_key_clean() - free gmp elements in key
 *
 * @param   key: pointer to key struct
 * @return
 */
int rsa_public_key_clean(struct rsa_public *key)
{
        if (!key)
                return -EINVAL;

        mpz_clears(key->n, key->e, NULL);

        return 0;
}

/**
 * rsa_private_key_dump() - dump key data to file stream
 *
 * @param   key: pointer to key struct
 * @param   stream: pointer to file stream
 * @return
 */
int rsa_private_key_dump(struct rsa_private *key, FILE *stream)
{
        if (!key)
                return -EINVAL;

        /*
         * ASN.1 style
         */
        gmp_fprintf(stream, "RSAPrivateKey ::= SEQUENCE {\n");
        gmp_fprintf(stream, "  version %lu\n", key->version);
        gmp_fprintf(stream, "  modulus %Zd, -- n\n", key->n);
        gmp_fprintf(stream, "  publicExponent %Zd, -- e\n", key->e);
        gmp_fprintf(stream, "  privateExponent %Zd, -- d\n", key->d);
        gmp_fprintf(stream, "  prime1 %Zd, -- p\n", key->p);
        gmp_fprintf(stream, "  prime2 %Zd, -- q\n", key->q);
        gmp_fprintf(stream, "  exponent1 %Zd, -- d mod (p-1)\n", key->exp1);
        gmp_fprintf(stream, "  exponent2 %Zd, -- d mod (q-1)\n", key->exp2);
        gmp_fprintf(stream, "  coefficient %Zd, -- (inverse of q) mod p }", key->coeff);
        gmp_fprintf(stream, "\n");
        gmp_fprintf(stream, "Version ::= %lu\n", key->version);

        return 0;
}

/**
 * rsa_private_key_save() - dump key data to file
 *
 * @param   key: pointer to key struct
 * @param   stream: file stream pointer
 * @return  0 on success
 */
int rsa_private_key_save(struct rsa_private *key, FILE *stream)
{
        return rsa_private_key_dump(key, stream);;
}

/**
 * rsa_public_key_dump() - dump key data to file stream
 * @param   key: pointer to key struct
 * @param   stream: pointer to file stream
 * @return
 */
int rsa_public_key_dump(struct rsa_public *key, FILE *stream)
{
        if (!key)
                return -EINVAL;

        /*
         * ASN.1 style
         */
        gmp_fprintf(stream, "RSAPublicKey ::= SEQUENCE {\n");
        gmp_fprintf(stream, "  modulus %Zd, -- n\n", key->n);
        gmp_fprintf(stream, "  publicExponent %Zd -- e }\n", key->e);

        return 0;
}

/**
 * rsa_public_key_save() - dump key data to file
 *
 * @param   key: pointer to key struct
 * @param   stream: pointer to file stream
 * @return  0 on success
 */
int rsa_public_key_save(struct rsa_public *key, FILE *stream)
{
        return rsa_public_key_dump(key, stream);;
}

/**
 * primality_test() - Solovay-Strassen primality test
 *
 * @param   n: a value to test
 * @param   k: determines the accuracy of the test
 * @return  1 on *probably* prime, 0 on composite
 */
int primality_test(const mpz_t n, uint64_t k)
{
        mpz_t a;
        mpz_t x;
        mpz_t t;

        mpz_inits(t, a, x, NULL);

        if (!mpz_cmp_ui(n, 1))
                return 0;

        if (!mpz_cmp_ui(n, 2))
                return 1;

        mpz_mod_ui(t, n, 2);
        if (!mpz_cmp_ui(t, 0))
                return 0;

        /* temporary variable */
        mpz_sub_ui(t, n, 2);
        while (k-- > 0) {
                /* choose a randomly in the range [2, n - 1] */
                __mpz_urandomm(a, t);
                mpz_add_ui(a, a, 2);

                mpz_set_ui(x, (uint64_t)mpz_jacobi(a, n));

                /* x == -1 */
                if (!mpz_cmp_si(x, -1)) {
                        mpz_set(x, n);
                        mpz_sub_ui(x, x, 1);
                }

                /*
                 * ( a^((n-1)/2) ) (mod n)
                 */
                if (mpz_cmp_ui(x, 0)) {
                        mpz_set(t, n);
                        mpz_sub_ui(t, t, 1);
                        mpz_div_ui(t, t, 2);

                        mpz_powm(a, a, t, n);

                        if (!mpz_cmp(a, x))
                                return 1;
                }
        }

        mpz_clears(t, a, x, NULL);

        return 0;
}

/**
 * generate_n_p_q() - generate N P Q factors in key
 *
 * @param   n: n to write
 * @param   p: p to write
 * @param   q: q to write
 * @param   k: binary length of n in octets
 * @return  0 on success
 */
int generate_n_p_q(mpz_t n, mpz_t p, mpz_t q, uint64_t k)
{
        uint64_t key_len;

        if (!n || !p || !q || !k)
                return -EINVAL;

        /* for the encryption process, k > 12 */
        if (k % 2 || k <= 12)
                return -EINVAL;

        key_len = k * 8;

        while (1) {
                mpz_rand_bitlen(p, key_len / 2);
                mpz_rand_bitlen(q, key_len / 2);

                mpz_mul(n, p, q);
                if (mpz_check_binlen(n, key_len))
                        continue;

                while (1) {
                        mpz_rand_bitlen(p, key_len / 2);

                        if (primality_test(p, PRIMALITY_TEST_ACCURACY) ==
                            NUM_COMPOSITE)
                                continue;

                        break;
                }

                while (1) {
                        mpz_rand_bitlen(q, key_len / 2);

                        if (primality_test(q, PRIMALITY_TEST_ACCURACY) ==
                            NUM_COMPOSITE)
                                continue;

                        break;
                }

                mpz_mul(n, p, q);
                if (!mpz_check_binlen(n, key_len))
                        break;
        }

        return 0;
}

/**
 * generate_e_d() - generate E and D factors
 *
 * @param   e: e to write
 * @param   d: d to write
 * @param   p: p factor
 * @param   q: q factor
 * @return  0 on success
 */
int generate_e_d(mpz_t e, mpz_t d, const mpz_t p, const mpz_t q)
{
        mpz_t phi;
        mpz_t p1;
        mpz_t q1;
        mpz_t t;

        if (!e || !d)
                return -EINVAL;

        mpz_inits(phi, p1, q1, t, NULL);

        /* phi = (p - 1) * (q - 1) */
        mpz_sub_ui(p1, p, 1);
        mpz_sub_ui(q1, q, 1);
        mpz_mul(phi, p1, q1);

        /* A very common choice for e is 65537 */
        mpz_set_ui(e, 65537);

        /* XXX: duplicated */
        mpz_gcd(t, e, phi);
        if (mpz_cmp_ui(t, 1)) {
                fprintf(stderr, "gcd() (e, phi) failed!\n");
                return -EFAULT;
        }

        mpz_invert(d, e, phi);

        /* test (e * d) % phi = 1 */
        mpz_mul(t, e, d);
        mpz_mod(t, t, phi);
        if (mpz_cmp_ui(t, 1)) {
                fprintf(stderr, "(e * d) %% phi = 1 failed!\n");
        }

        mpz_clears(phi, p1, q1, t, NULL);

        return 0;
}

/**
 * generate_exp_coef() - generate other elements in key
 *
 * @param   key: pointer to key struct
 * @return
 */
int generate_exp_coef(struct rsa_private *key)
{
        mpz_t t;

        mpz_inits(t, NULL);

        if (!key)
                return -EINVAL;

        mpz_sub_ui(t, key->p, 1);
        mpz_mod(key->exp1, key->d, t);

        mpz_sub_ui(t, key->q, 1);
        mpz_mod(key->exp2, key->d, t);

        mpz_invert(key->coeff, key->q, key->p);

//        mpz_sub_ui(t, key->p, 2);
//        mpz_powm(t, key->q, t, key->p);
//        gmp_printf("coef: %Zd\n", t);

        mpz_clears(t, NULL);

        return 0;
}

/**
 * rsa_private_key_generate() - generate rsa private key
 *
 * @param   key: pointer to private key struct
 * @param   length: length of key in bits
 * @return  0 on success
 */
int rsa_private_key_generate(struct rsa_private *key, uint64_t length)
{
        if (!key)
                return -EINVAL;

        key->key_len = length;
        key->version = 0x00;    /* RFC2313 */

        if (generate_n_p_q(key->n, key->p, key->q, length / 8)) {
                fprintf(stderr, "failed to generate N, P, Q elements\n");
                return -EFAULT;
        }

        if (generate_e_d(key->e, key->d, key->p, key->q)) {
                fprintf(stderr, "failed to generate E, Q elements\n");
                return -EFAULT;
        }

        generate_exp_coef(key);

        return 0;
}

/**
 * rsa_public_key_generate() - generate public key from private key
 *
 * @param   pub: pointer to public key struct
 * @param   priv: pointer to private key struct
 * @return  0 on success
 */
int rsa_public_key_generate(struct rsa_public *pub, struct rsa_private *priv)
{
        if (!pub || !priv)
                return -EINVAL;

        mpz_set(pub->n, priv->n);
        mpz_set(pub->e, priv->e);
        pub->key_len = priv->key_len;

        return 0;
}