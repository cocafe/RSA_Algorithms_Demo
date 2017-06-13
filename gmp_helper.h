#ifndef SIMPLERSADIGEST_GMP_HELPER_H
#define SIMPLERSADIGEST_GMP_HELPER_H

#ifndef _STDINT_H
#error include <stdint.h> first
#endif /* _STDINT_H */

uint64_t urandom_read(void);

void __mpz_urandomb(mpz_t rop, mp_bitcnt_t n);
void __mpz_urandomm(mpz_t rop, const mpz_t n);

int mpz_rand_bitlen(mpz_t rop, uint64_t len);
int mpz_check_binlen(const mpz_t src, uint64_t len);

#endif //SIMPLERSADIGEST_GMP_HELPER_H
