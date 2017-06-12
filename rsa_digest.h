#ifndef SIMPLERSADIGEST_RSA_DIGEST_H
#define SIMPLERSADIGEST_RSA_DIGEST_H

#ifndef __GMP_H__
#error include gmp.h first
#endif /* __GMP_H__ */

#ifndef SIMPLERSADIGEST_GMP_HELPER_H
#error include gmp_helper.h first
#endif /* SIMPLERSADIGEST_GMP_HELPER_H */

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
        mpz_t           coef;           /* (inverse of q) mod p */
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

int rsa_encrypt_file(const char *file_encrypt,
                     const char *file_plain,
                     const mpz_t e,
                     const mpz_t n,
                     uint64_t key_len);

int rsa_decrypt_file(const char *file_decrypt,
                     const char *file_encrypt,
                     const mpz_t e,
                     const mpz_t n,
                     uint64_t key_len);

#endif //SIMPLERSADIGEST_RSA_DIGEST_H
