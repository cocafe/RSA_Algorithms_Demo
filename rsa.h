/**
 * rsa.h - RSA public functions header
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

#ifndef SIMPLERSADIGEST_RSA_DIGEST_H
#define SIMPLERSADIGEST_RSA_DIGEST_H

#include "gmp_helper.h"
#include "misc_helper.h"

#define PRIMALITY_TEST_ACCURACY                 (5)

enum {
        NUM_COMPOSITE = 0,
        NUM_PRIME,
};

struct rsa_private {
        uint64_t        key_len;        /* key bit length */
        uint64_t        version;        /* RSA version */
        mpz_t           n;              /* modulus */
        mpz_t           p;              /* prime1 */
        mpz_t           q;              /* prime2 */
        mpz_t           e;              /* public exponent */
        mpz_t           d;              /* private exponent */
        mpz_t           exp1;           /* exponent1: d mod (p-1) */
        mpz_t           exp2;           /* exponent2: d mod (q-1) */
        mpz_t           coeff;          /* Chinese Remainder Theorem
                                         * coefficient: (inverse of q) mod p */
};

struct rsa_public {
        uint64_t        key_len;        /* key bit length */
        mpz_t           n;              /* modulus */
        mpz_t           e;              /* public exponent */
};

int rsa_private_key_init(struct rsa_private *key);
int rsa_private_key_clean(struct rsa_private *key);

int rsa_public_key_init(struct rsa_public *key);
int rsa_public_key_clean(struct rsa_public *key);

int rsa_private_key_dump(struct rsa_private *key, FILE *stream);
int rsa_private_key_save(struct rsa_private *key, FILE *stream);

int rsa_public_key_dump(struct rsa_public *key, FILE *stream);
int rsa_public_key_save(struct rsa_public *key, FILE *stream);

int rsa_private_key_generate(struct rsa_private *key, uint64_t length);
int rsa_public_key_generate(struct rsa_public *pub, struct rsa_private *priv);

/**
 *
 * Structure of encryption-block
 *
 *         0     1    2...
 *    EB = 00 || BT || PS || 00 || D
 *        octet
 *
 * Octet length of EB = k
 +
 */
struct rsa_encrypt_block {
        uint8_t *octet;         /* aka byte */
        uint64_t k;
};

enum {
        BT_TYPE_00 = 0x00,
        BT_TYPE_01 = 0x01,
        BT_TYPE_02 = 0x02,
        NUM_BT_TYPE,
};

enum {
        RSA_KEY_TYPE_PRIVATE = 0,
        RSA_KEY_TYPE_PUBLIC,
        NUM_RSA_KEY_TYPE
};

#define EB_BT_OCTET_OFFSET              (1 << 0)
#define EB_PS_OCTET_OFFSET              (1 << 1)

#define PRIVATE_KEY_BT_DEFAULT          (BT_TYPE_01)
#define PUBLIC_KEY_BT_DEFAULT           (BT_TYPE_02)

int rsa_encrypt_file(FILE *stream_encrypted,
                     FILE *stream_plain,
                     const mpz_t c,
                     const mpz_t n,
                     uint64_t key_len,
                     uint8_t key_type,
                     uint8_t BT);
int rsa_decrypt_file(FILE *stream_decrypt,
                     FILE *stream_encrypt,
                     const mpz_t c,
                     const mpz_t n,
                     uint64_t key_len,
                     uint8_t key_type);

int rsa_private_key_encrypt(struct rsa_private *key, FILE *stream_encrypted,
                            FILE *stream_plain);
int rsa_private_key_decrypt(struct rsa_private *key, FILE *stream_decrypt,
                            FILE *stream_encrypt);

int rsa_public_key_encrypt(struct rsa_public *key,FILE *stream_encrypted,
                           FILE *stream_plain);
int rsa_public_key_decrypt(struct rsa_public *key,FILE *stream_decrypt,
                           FILE *stream_encrypt);

#endif //SIMPLERSADIGEST_RSA_DIGEST_H
