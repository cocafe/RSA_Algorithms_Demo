#ifndef SIMPLERSADIGEST_RSA_DIGEST_H
#define SIMPLERSADIGEST_RSA_DIGEST_H

#ifndef __GMP_H__
#error include gmp.h first
#endif /* __GMP_H__ */

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

int rsa_private_key_dump(struct rsa_private *key, FILE *__stream);
int rsa_private_key_save(struct rsa_private *key, const char *filename);

int rsa_public_key_dump(struct rsa_public *key, FILE *__stream);
int rsa_public_key_save(struct rsa_public *key, const char *filename);

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

#define EB_BT_OCTET_OFFSET              (1 << 0)
#define EB_PS_OCTET_OFFSET              (1 << 1)

#define PRIVATE_KEY_BT_DEFAULT          (BT_TYPE_01)
#define PUBLIC_KEY_BT_DEFAULT           (BT_TYPE_02)

int rsa_encrypt_file(const char *file_encrypt,
                     const char *file_plain,
                     const mpz_t c,
                     const mpz_t n,
                     uint64_t key_len,
                     uint8_t BT);
int rsa_decrypt_file(const char *file_decrypt,
                     const char *file_encrypt,
                     const mpz_t c,
                     const mpz_t n,
                     uint64_t key_len);

int rsa_private_key_encrypt(struct rsa_private *key,
                            const char *file_encrypt,
                            const char *file_plain);
int rsa_private_key_decrypt(struct rsa_private *key,
                            const char *file_decrypt,
                            const char *file_encrypt);

int rsa_public_key_encrypt(struct rsa_public *key,
                           const char *file_encrypt,
                           const char *file_plain);
int rsa_public_key_decrypt(struct rsa_public *key,
                           const char *file_decrypt,
                           const char *file_encrypt);

#endif //SIMPLERSADIGEST_RSA_DIGEST_H
