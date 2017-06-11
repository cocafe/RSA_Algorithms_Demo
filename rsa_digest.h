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
        mpz_t n;
        mpz_t p;
        mpz_t q;
        mpz_t e;
        mpz_t d;
};

struct rsa_private {
        mpz_t n;
        mpz_t e;
};

struct rsa_public {
        mpz_t n;
        mpz_t d;
};

#endif //SIMPLERSADIGEST_RSA_DIGEST_H
