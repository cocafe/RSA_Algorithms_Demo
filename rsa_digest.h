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

struct rsa_key {
        uint64_t        key_len;
        mpz_t           n;
        mpz_t           p;
        mpz_t           q;
        mpz_t           e;
        mpz_t           d;
};

struct rsa_public {
        uint64_t        key_len;
        mpz_t           n;
        mpz_t           d;
};

struct rsa_private {
        uint64_t        key_len;
        mpz_t           n;
        mpz_t           e;
};

int rsa_key_init(struct rsa_key *key);
int rsa_key_clean(struct rsa_key *key);

int rsa_public_key_init(struct rsa_public *key);
int rsa_public_key_clean(struct rsa_public *key);

int rsa_private_key_init(struct rsa_private *key);
int rsa_private_key_clean(struct rsa_private *key);

int rsa_key_dump(struct rsa_key *key);
int rsa_key_save(struct rsa_key *key, const char *filename);
int rsa_public_key_save(struct rsa_public *key, const char *filename);
int rsa_private_key_save(struct rsa_private *key, const char *filename);

int generate_key(struct rsa_key *key, uint64_t len_key);
int generate_public_key(struct rsa_key *key, struct rsa_public *pkey);
int generate_private_key(struct rsa_key *key, struct rsa_private *pkey);

#endif //SIMPLERSADIGEST_RSA_DIGEST_H
