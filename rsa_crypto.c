#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>

#include <gmp.h>

#include "rsa.h"

/**
 * rsa_encrypt_block_init() - alloc memory space for encryption block
 *
 * @param   blk: pointer to EB
 * @param   k: block octet length, key length div 8
 * @return  0 on success
 */
int rsa_encrypt_block_init(struct rsa_encrypt_block *blk, uint64_t k)
{
        if (!blk)
                return -EINVAL;

        blk->k = k;
        blk->octet = (uint8_t *)calloc(k, sizeof(uint8_t));
        if (!blk->octet)
                return -ENOMEM;

        return 0;
}

/**
 * rsa_encryption_free() - free allocated memory of encryption block
 *
 * @param   blk: pointer to EB
 * @return  0 on success
 */
int rsa_encrypt_block_free(struct rsa_encrypt_block *blk)
{
        if (!blk)
                return -EINVAL;

        if (blk->octet) {
                free(blk->octet);
                blk->octet = NULL;
                blk->k = 0;
        }

        return 0;
}

/**
 * rsa_encrypt_block_reset() - clear allocated memory space
 *
 * @param   blk: pointer to EB
 * @return  0 on success
 */
int rsa_encrypt_block_clear(struct rsa_encrypt_block *blk)
{
        if (!blk)
                return -EINVAL;

        if (!blk->octet)
                return -ENODATA;

        memset(blk->octet, 0x00, sizeof(uint8_t) * blk->k);

        return 0;
}

/**
 * rsa_encrypt_block_encode() - put data into EB
 *
 * @param   EB: pointer to encryption block
 * @param   BT: encryption block type
 * @param   D: data in uint8_t
 * @return  0 on success
 */
int rsa_encrypt_block_encode(struct rsa_encrypt_block *EB, const uint8_t BT, const uint8_t D)
{
        uint64_t octet_data;
        uint64_t octet_pad;
        uint8_t pad;
        int32_t idx;

        if (!EB)
                return -EINVAL;

        if (BT >= NUM_BT_TYPE)
                return -EINVAL;

        idx = 0;

        EB->octet[idx++] = 0x00;           /* 00 */
        EB->octet[idx++] = BT;             /* BT */

        octet_data = sizeof(D);
        octet_pad = EB->k - 3 - octet_data;

        if ((int64_t)octet_pad < 0)
                return -EFAULT;

        /* PS */
        while (idx < (octet_pad + EB_PS_OCTET_OFFSET)) {
                switch (BT) {
                        case BT_TYPE_00:
                                /* BT_00 pad PS with 0x00 */
                                pad = 0x00;

                                break;

                        case BT_TYPE_01:
                                /* BT_01 pad PS with 0xFF */
                                pad = 0xFF;

                                break;

                        case BT_TYPE_02:
                                do {
                                        /*
                                         * BT_02 pad PS with randomly
                                         * but non-zero
                                         */
                                        pad = (uint8_t)urandom_read();
                                } while (pad == 0);

                                break;

                        default:
                                pad = 0x00; /* never */
                                break;
                }

                EB->octet[idx++] = pad;
        }

        EB->octet[idx++] = 0x00;           /* 00 */
        EB->octet[idx] = D;                /* D */

        return 0;
}

/**
 * rsa_encrypt_block_decode() - get data segment from EB
 *
 * FIXME: we only support single uint8_t data right now
 *
 * @param   EB: pointer to encryption block
 * @param   D: pointer to data
 * @return  0 on success
 */
int rsa_encrypt_block_decode(struct rsa_encrypt_block *EB, uint8_t *D)
{
        int32_t found;
        int32_t idx;
        uint8_t BT;

        if (!EB)
                return -EINVAL;

        BT = EB->octet[EB_BT_OCTET_OFFSET];

        if (BT >= NUM_BT_TYPE)
                return -EINVAL;

        /* Search starts from PS segment */
        for (idx = EB_PS_OCTET_OFFSET, found = 0; idx < EB->k; idx++) {
                switch (BT) {
                        case BT_TYPE_00:
                                /* We are on data segment */
                                if (EB->octet[idx] != 0x00) {
                                        found = 1;
                                }

                                break;

                        case BT_TYPE_01:
                        case BT_TYPE_02:
                        default:
                                if (EB->octet[idx] == 0x00) {
                                        found = 1;
                                        idx++; /* Move to data seg */
                                }

                                break;
                }

                if (found)
                        break;
        }

        if (!found)
                return -ENODATA;

        // FIXME: data length is not given
        for (int j = 0; idx < EB->k; idx++) {
                D[j] = EB->octet[idx];
        }

        return 0;
}

/**
 * rsa_encrypt_block_dump() - dump encryption block data to stdout
 *
 * @param   blk: pointer to encryption block
 * @return
 */
int rsa_encrypt_block_dump(struct rsa_encrypt_block *blk)
{
        if (!blk)
                return -EINVAL;

        printf("(k=%lu) ", blk->k);

        for (int i = 0; i < blk->k; ++i) {
                printf("%02x ", blk->octet[i]);
        }

        printf("\n");

        return 0;
}

/**
 * rsa_entrypt_block_convert_string() - convert encryption block to string
 *
 * XXX: remember to free the the memory str allocated
 *
 * @param   blk: pointer to encryption block
 * @param   str: pointer to char pointer
 * @return  0 on success
 */
int rsa_encrypt_block_convert_string(struct rsa_encrypt_block *blk, char **str)
{
        char octet[2];
        char *buf;

        if (!blk)
                return -EINVAL;

        buf = (char *)calloc(blk->k * 2 + 2, sizeof(char));
        if (!buf)
                return -ENOMEM;

        *str = buf;

        for (int i = 0, j = 0; i < blk->k; ++i, j += 2) {
                sprintf(octet, "%02x", blk->octet[i]);
                memcpy(&buf[j], octet, sizeof(octet));
        }



        return 0;
}

/**
 * rsa_encrypt_block_convert_integer() - convert EB to GMP integer
 *
 * @param   EB: pointer to encryption block
 * @param   x: GMP integer to write to
 * @return  0 on success
 */
int rsa_encrypt_block_convert_integer(struct rsa_encrypt_block *EB, mpz_t x)
{
        mpz_t t;
        mpz_t res;

        mpz_inits(t, res, NULL);

        if (!EB)
                return -EINVAL;

        /*                     k
         * x = SUM 2^(8(k-i)) EBi
         *                    i=1
         */
        for (int i = 0; i < EB->k; ++i) {
                mpz_set_ui(t, 2);
                mpz_pow_ui(t, t, 8 * (EB->k - (i + 1)));
                mpz_mul_ui(t, t, EB->octet[i]);

                mpz_add(res, res, t);
        }

        mpz_set(x, res);
        mpz_clears(t, res, NULL);

        return 0;
}

/**
 * rsa_encrypt_block_from_integer() - create encryption block from GMP integer
 *
 * @param   EB: pointer to encryption block
 * @param   y: pointer to GMP integer
 * @return  0 on success
 */
int rsa_encrypt_block_from_integer(struct rsa_encrypt_block *EB, const mpz_t y)
{
        mpz_t t;
        mpz_t r;

        mpz_inits(t, r, NULL);

        if (!EB || !y)
                return -EINVAL;

        if (!EB->octet || !EB->k)
                return -ENODATA;

        /*                     k
         * y = SUM 2^(8(k-i)) EDi
         *                    i=1
         */
        for (int i = 0; i < EB->k; ++i) {
                mpz_set(t, y);
                mpz_div_2exp(r, t, (EB->k - (i + 1)) * 8);

                EB->octet[i] = (uint8_t)mpz_get_ui(r);

                mpz_mul_2exp(r, r, (EB->k - (i + 1)) * 8);
                mpz_sub(t, t, r);
        }

        mpz_clears(t, r, NULL);

        return 0;
}

/**
 * rsa_encrypt_block_from_string() - create a encryption block from string
 *
 * @param   EB: pointer to encryption block
 * @param   str: pointer to string
 * @return  0 on success
 */
int rsa_encrypt_block_from_string(struct rsa_encrypt_block *EB, const char *str)
{
        mpz_t t;

        mpz_inits(t, NULL);

        if (!EB)
                return -EINVAL;

        if (!str)
                return -EINVAL;

        if (strlen(str) < EB->k * 2)
                return -EINVAL;

        mpz_set_str(t, str, 16);

        rsa_encrypt_block_from_integer(EB, t);

        mpz_clears(t, NULL);

        return 0;
}

/**
 * rsa_computation() - rsa encryption algorithm
 *
 * @param   y: output data
 * @param   x: input data
 * @param   c: D or E exponent from key
 * @param   n: N from key
 */
static inline void rsa_computation(mpz_t y, const mpz_t x, const mpz_t c, const mpz_t n)
{
        mpz_powm(y, x, c, n);
}

/**
 * rsa_encrypt_file() - rsa algorithm to encrypt file
 *
 * @param   file_encrypt: file path to save encrypted data
 * @param   file_plain: file path to plain text file
 * @param   c: E or D exponent from key
 * @param   n: N modulus from key
 * @param   key_len: key bit length from key
 * @param   BT: 00 01 for private key operation, 02 for public key operation
 * @return  0 on success
 */
int rsa_encrypt_file(const char *file_encrypt,
                     const char *file_plain,
                     const mpz_t c,
                     const mpz_t n,
                     uint64_t key_len,
                     uint8_t BT)
{
        struct rsa_encrypt_block        EB;     /* Formatted block */
        struct rsa_encrypt_block        ED;     /* Encrypted block*/
        FILE                            *fp_encrypt;
        FILE                            *fp_plain;
        char                            *str_encrypt;
        mpz_t                           data_encrypt;
        mpz_t                           data_plain;
        mpz_t                           x;      /* Integer encryption block */
        mpz_t                           y;      /* Encrypted integer block */
        int32_t                         ret = 0;
        int32_t                         read;   /* fgetc() returns int32_t */
        uint8_t                         ch;     /* char reads from file */

        if (!file_encrypt || !file_plain || !c || !n)
                return -EINVAL;

        fp_plain = fopen(file_plain, "r");
        if (!fp_plain) {
                fprintf(stderr, "failed to open %s to read\n", file_plain);
                return -EACCES;
        }

        fp_encrypt = fopen(file_encrypt, "w");
        if (!fp_encrypt) {
                fprintf(stderr, "failed to open %s to write\n", file_encrypt);
                ret = -EACCES;

                goto err_fpencrypt;
        }

        mpz_inits(data_encrypt, data_plain, x, y, NULL);
        rsa_encrypt_block_init(&EB, key_len / 8);
        rsa_encrypt_block_init(&ED, key_len / 8);

        do {
                read = fgetc(fp_plain);
                if (read == EOF)
                        break;

                ch = (uint8_t)read;

                mpz_set_ui(data_plain, ch);

                rsa_encrypt_block_clear(&EB);
                rsa_encrypt_block_clear(&ED);

                rsa_encrypt_block_encode(&EB, BT, ch);
                rsa_encrypt_block_convert_integer(&EB, x);
                rsa_computation(y, x, c, n);
                rsa_encrypt_block_from_integer(&ED, y);
                rsa_encrypt_block_convert_string(&ED, &str_encrypt);

                gmp_printf("encrypt: [%#04Zx][%c] -> [%s]\n", data_plain, ch, str_encrypt);

                fprintf(fp_encrypt, "%s\n", str_encrypt);
                free(str_encrypt);
        } while (!feof(fp_plain));

        rsa_encrypt_block_free(&EB);
        rsa_encrypt_block_free(&ED);
        mpz_clears(data_encrypt, data_plain, x, y, NULL);

        fflush(fp_encrypt);
        fclose(fp_encrypt);

err_fpencrypt:
        fclose(fp_plain);

        return ret;
}

/**
 * rsa_decrypt_file() - decrypt rsa encrypted file
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
        struct rsa_encrypt_block        EB;     /* Decoded encryption block */
        struct rsa_encrypt_block        ED;     /* Encoded encryption block */
        FILE                            *fp_decrypt;
        FILE                            *fp_encrypt;
        char                            *str_encrypt;
        size_t                          str_len;
        mpz_t                           x;      /* Decrypted integer block */
        mpz_t                           y;      /* Encrypted integer block */
        int32_t                         ret = 0;
        int32_t                         read;
        int32_t                         count;  /* String iterator */
        uint8_t                         ch;
        uint8_t                         D;      /* Decrypted data */

        fp_encrypt = fopen(file_encrypt, "r");
        if (!fp_encrypt) {
                fprintf(stderr, "failed to open %s to read\n", file_encrypt);
                return -EACCES;
        }

        fp_decrypt = fopen(file_decrypt, "w");
        if (!fp_decrypt) {
                fprintf(stderr, "failed to open %s to write\n", file_decrypt);
                ret = -EACCES;

                goto err_fpdecrypt;
        }

        /* Char is in hex, + [\n] + [\0] */
        str_len = (sizeof(char) * key_len / 4) + 2;
        str_encrypt = (char *)calloc(1, str_len);
        if (!str_encrypt) {
                ret = -ENOMEM;
                goto err_buffer;
        }

        mpz_inits(x, y, NULL);
        rsa_encrypt_block_init(&EB, key_len / 8);
        rsa_encrypt_block_init(&ED, key_len / 8);

        count = 0;
        do {
                read = fgetc(fp_encrypt);
                if (read == EOF)
                        break;

                // FIXME: we might read non ASCII code...
                ch = (uint8_t)read;
                if (ch == '\n') {
                        rsa_encrypt_block_clear(&EB);
                        rsa_encrypt_block_clear(&ED);

                        rsa_encrypt_block_from_string(&ED, str_encrypt);
                        rsa_encrypt_block_convert_integer(&ED, y);
                        rsa_computation(x, y, c, n);
                        rsa_encrypt_block_from_integer(&EB, x);
                        rsa_encrypt_block_decode(&EB, &D);

                        fputc(D, fp_decrypt);

                        printf("decrypt: [%s] -> [%#04x][%c]\n", str_encrypt, D, D);

                        memset(str_encrypt, 0x00, str_len);
                        count = 0;
                } else {
                        str_encrypt[count] = ch;
                        count++;
                }

                if (count >= str_len) {
                        fprintf(stderr, "string reading overflow\n");
                        ret = -E2BIG;

                        goto err_read;
                }
        } while (!feof(fp_encrypt));

err_read:
        rsa_encrypt_block_free(&ED);
        rsa_encrypt_block_free(&EB);
        mpz_clears(x, y, NULL);

        free(str_encrypt);

err_buffer:
        fflush(fp_decrypt);
        fclose(fp_decrypt);

err_fpdecrypt:
        fclose(fp_encrypt);

        return ret;
}

int rsa_private_key_encrypt(struct rsa_private *key,
                            const char *file_encrypt,
                            const char *file_plain)
{
        return rsa_encrypt_file(file_encrypt,
                                file_plain,
                                key->d,
                                key->n,
                                key->key_len,
                                PRIVATE_KEY_BT_DEFAULT);
}

int rsa_private_key_decrypt(struct rsa_private *key,
                            const char *file_decrypt,
                            const char *file_encrypt)
{
        return rsa_decrypt_file(file_decrypt,
                                file_encrypt,
                                key->d,
                                key->n,
                                key->key_len);
}

int rsa_public_key_encrypt(struct rsa_public *key,
                           const char *file_encrypt,
                           const char *file_plain)
{
        return rsa_encrypt_file(file_encrypt,
                                file_plain,
                                key->e,
                                key->n,
                                key->key_len,
                                PUBLIC_KEY_BT_DEFAULT);
}

int rsa_public_key_decrypt(struct rsa_public *key,
                           const char *file_decrypt,
                           const char *file_encrypt)
{
        return rsa_decrypt_file(file_decrypt,
                                file_encrypt,
                                key->e,
                                key->n,
                                key->key_len);
}