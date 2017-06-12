#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <gmp.h>

#include "rsa.h"

/**
 * rsa_docrypto() - rsa en/decrypt
 *
 * @param   out: output data
 * @param   in: input data
 * @param   c: e or d exponent from key
 * @param   n: n from key
 */
void rsa_docrypto(mpz_t out, const mpz_t in, const mpz_t c, const mpz_t n)
{
        mpz_powm(out, in, c, n);
}

/**
 * rsa_encrypt_file() - encrypt file with RSA algorithm
 *
 * @param   file_crypt: encrypted file path
 * @param   file_plain: file to encrypt
 * @param   c: E or D exponent in key
 * @param   n: N modulus in key
 * @param   key_len: length of key
 * @return  0 on success
 */
int rsa_encrypt_file(const char *file_encrypt,
                     const char *file_plain,
                     const mpz_t c,
                     const mpz_t n,
                     uint64_t key_len)
{
        FILE *fcrypt;
        FILE *fplain;
        mpz_t dcrypt;
        mpz_t dplain;
        int32_t res;
        uint8_t ch;

        if (!file_encrypt || !file_plain || !c || !n)
                return -EINVAL;

        fplain = fopen(file_plain, "r");
        if (!fplain) {
                fprintf(stderr, "failed to open %s to read\n", file_plain);
                return -EACCES;
        }

        fcrypt = fopen(file_encrypt, "w");
        if (!fcrypt) {
                fprintf(stderr, "failed to open %s to write\n", file_encrypt);
                return -EACCES;
        }

        mpz_inits(dcrypt, dplain, NULL);

        while (!feof(fplain)) {
                res = fgetc(fplain);
                if (res == EOF)
                        break;

                ch = (uint8_t)res;

                mpz_set_ui(dplain, ch);

                rsa_docrypto(dcrypt, dplain, c, n);
                gmp_fprintf(fcrypt, "%Zx\n", dcrypt);
        }

        fflush(fcrypt);
        fclose(fplain);
        fclose(fcrypt);

        mpz_clears(dcrypt, dplain, NULL);

        return 0;
}

/**
 * rsa_decrypt_file() - decrypt file with RSA algorithm
 *
 * @param   file_decrypt: file path to save decrypted data
 * @param   file_encrypt: file path to encrypted file
 * @param   c: E or D exponent from key
 * @param   n: N modulus from key
 * @param   key_len: key bit length
 * @return  0 on success
 */
int rsa_decrypt_file(const char *file_decrypt,
                     const char *file_encrypt,
                     const mpz_t c,
                     const mpz_t n,
                     uint64_t key_len)
{
        FILE *fencry;
        FILE *fdecry;
        mpz_t dencry;
        mpz_t ddecry;
        uint8_t ch;

        if (!file_decrypt || !file_encrypt || !c || !n)
                return -EINVAL;

        fencry = fopen(file_encrypt, "r");
        if (!fencry) {
                fprintf(stderr, "failed to open %s to read\n", file_encrypt);
                return -EACCES;
        }

        fdecry = fopen(file_decrypt, "w");
        if (!fdecry) {
                fprintf(stderr, "failed to open %s to write\n", file_decrypt);
                return -EACCES;
        }

        mpz_inits(dencry, ddecry, NULL);

        while (!feof(fencry)) {
                gmp_fscanf(fencry, "%Zx", dencry);
                if (feof(fencry))
                        break;

                rsa_docrypto(ddecry, dencry, c, n);
                ch = (uint8_t)mpz_get_ui(ddecry);
                fputc(ch, fdecry);
        }

        fflush(fdecry);
        fclose(fencry);
        fclose(fdecry);

        mpz_clears(dencry, ddecry, NULL);

        return 0;
}