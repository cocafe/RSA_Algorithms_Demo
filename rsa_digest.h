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

#endif //SIMPLERSADIGEST_RSA_DIGEST_H
