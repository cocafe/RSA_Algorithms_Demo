/**
 * sha512.c - Compute SHA384 and SHA512 message digest of file or memory block
 *
 *      Author: cocafe <cocafehj@gmail.com> 2016
 *
 * Referred <sha512.c> from <coreuitls>
 * Reference: <https://tools.ietf.org/html/rfc6234>
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "sha512.h"
#include "misc_helper.h"

#ifndef UINT64_MAX
#warning the code may break on system lacking 64bit native support
#warning we also don't provide native uint64_t-like support yet
#endif

/* Define some short use of types */
typedef int8_t   s8;
typedef int16_t  s16;
typedef int32_t  s32;
typedef int64_t  s64;

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;

/* Trivial bit operation on native 64bit integer implementation */
#define u64and(x, y)                    ((x) & (y))
#define u64or(x, y)                     ((x) | (y))
#define u64xor(x, y)                    ((x) ^ (y))
#define u64shl(x, n)                    ((x) << (n))
#define u64shr(x, n)                    ((x) >> (n))
#define u64not(x)                       (~(x))
#define u64rotr(x, n)                   (((x) >> (n)) | ((x) << (64 - n)))
#define u64rotl(x, n)                   (((x) << (n)) | ((x) >> (64 - n)))
#define u64hi(x)                        ((u64)((x) >> 32))
#define u64lo(x)                        ((x) & (u64)(UINT32_MAX))
#define u64hilo(hi, lo)                 (((u64)(hi) << 32) + (u64)(lo))
#define u64init(hi, lo)                 u64hilo(hi, lo)

#define u64swp(n)                                                       \
    u64or (u64or (u64or (u64shl (n, 56),                                \
                         u64shl (u64and (n, u64lo (0x0000ff00)), 40)),  \
                  u64or (u64shl (u64and (n, u64lo (0x00ff0000)), 24),   \
                         u64shl (u64and (n, u64lo (0xff000000)),  8))), \
           u64or (u64or (u64and (u64shr (n,  8), u64lo (0xff000000)),   \
                         u64and (u64shr (n, 24), u64lo (0x00ff0000))),  \
                  u64or (u64and (u64shr (n, 40), u64lo (0x0000ff00)),   \
                         u64shr (n, 56))))

#define u64bele(n)                      u64swp(n)
#define u64lebe(n)                      u64swp(n)

#define BITS(x)                         (x)
#define BYTES(x)                        (x)
#define BYTE_TO_BIT(x)                  ((x) * 8)
#define BIT_TO_BYTE(x)                  ((x) / 8)

#define SHA384_HASH_BYTE                BIT_TO_BYTE(SHA384_HASH_BITS)
#define SHA512_HASH_BYTE                BIT_TO_BYTE(SHA512_HASH_BITS)

#define PROCESS_BLOCK_SIZE              (BYTES(128))

/*
 * This is the [1] and K[0] padding block
 * before the 128-bit whole message length block
 */
static const u8 padding_blk[128] = { 0x80, 0 /* , 0, 0, ...  */ };

/**
 * SHA-384/512 round constants (K0 ~ K79)
 */
static u64 const sha512_round_constants[80] = {
        u64init(0x428a2f98, 0xd728ae22), u64init(0x71374491, 0x23ef65cd),
        u64init(0xb5c0fbcf, 0xec4d3b2f), u64init(0xe9b5dba5, 0x8189dbbc),
        u64init(0x3956c25b, 0xf348b538), u64init(0x59f111f1, 0xb605d019),
        u64init(0x923f82a4, 0xaf194f9b), u64init(0xab1c5ed5, 0xda6d8118),
        u64init(0xd807aa98, 0xa3030242), u64init(0x12835b01, 0x45706fbe),
        u64init(0x243185be, 0x4ee4b28c), u64init(0x550c7dc3, 0xd5ffb4e2),
        u64init(0x72be5d74, 0xf27b896f), u64init(0x80deb1fe, 0x3b1696b1),
        u64init(0x9bdc06a7, 0x25c71235), u64init(0xc19bf174, 0xcf692694),
        u64init(0xe49b69c1, 0x9ef14ad2), u64init(0xefbe4786, 0x384f25e3),
        u64init(0x0fc19dc6, 0x8b8cd5b5), u64init(0x240ca1cc, 0x77ac9c65),
        u64init(0x2de92c6f, 0x592b0275), u64init(0x4a7484aa, 0x6ea6e483),
        u64init(0x5cb0a9dc, 0xbd41fbd4), u64init(0x76f988da, 0x831153b5),
        u64init(0x983e5152, 0xee66dfab), u64init(0xa831c66d, 0x2db43210),
        u64init(0xb00327c8, 0x98fb213f), u64init(0xbf597fc7, 0xbeef0ee4),
        u64init(0xc6e00bf3, 0x3da88fc2), u64init(0xd5a79147, 0x930aa725),
        u64init(0x06ca6351, 0xe003826f), u64init(0x14292967, 0x0a0e6e70),
        u64init(0x27b70a85, 0x46d22ffc), u64init(0x2e1b2138, 0x5c26c926),
        u64init(0x4d2c6dfc, 0x5ac42aed), u64init(0x53380d13, 0x9d95b3df),
        u64init(0x650a7354, 0x8baf63de), u64init(0x766a0abb, 0x3c77b2a8),
        u64init(0x81c2c92e, 0x47edaee6), u64init(0x92722c85, 0x1482353b),
        u64init(0xa2bfe8a1, 0x4cf10364), u64init(0xa81a664b, 0xbc423001),
        u64init(0xc24b8b70, 0xd0f89791), u64init(0xc76c51a3, 0x0654be30),
        u64init(0xd192e819, 0xd6ef5218), u64init(0xd6990624, 0x5565a910),
        u64init(0xf40e3585, 0x5771202a), u64init(0x106aa070, 0x32bbd1b8),
        u64init(0x19a4c116, 0xb8d2d0c8), u64init(0x1e376c08, 0x5141ab53),
        u64init(0x2748774c, 0xdf8eeb99), u64init(0x34b0bcb5, 0xe19b48a8),
        u64init(0x391c0cb3, 0xc5c95a63), u64init(0x4ed8aa4a, 0xe3418acb),
        u64init(0x5b9cca4f, 0x7763e373), u64init(0x682e6ff3, 0xd6b2b8a3),
        u64init(0x748f82ee, 0x5defb2fc), u64init(0x78a5636f, 0x43172f60),
        u64init(0x84c87814, 0xa1f0ab72), u64init(0x8cc70208, 0x1a6439ec),
        u64init(0x90befffa, 0x23631e28), u64init(0xa4506ceb, 0xde82bde9),
        u64init(0xbef9a3f7, 0xb2c67915), u64init(0xc67178f2, 0xe372532b),
        u64init(0xca273ece, 0xea26619c), u64init(0xd186b8c7, 0x21c0c207),
        u64init(0xeada7dd6, 0xcde0eb1e), u64init(0xf57d4f7f, 0xee6ed178),
        u64init(0x06f067aa, 0x72176fba), u64init(0x0a637dc5, 0xa2c898a6),
        u64init(0x113f9804, 0xbef90dae), u64init(0x1b710b35, 0x131c471b),
        u64init(0x28db77f5, 0x23047d84), u64init(0x32caab7b, 0x40c72493),
        u64init(0x3c9ebe0a, 0x15c9bebc), u64init(0x431d67c4, 0x9c100d4c),
        u64init(0x4cc5d4be, 0xcb3e42b6), u64init(0x597f299c, 0xfc657e2a),
        u64init(0x5fcb6fab, 0x3ad6faec), u64init(0x6c44198c, 0x4a475817),
};

#define K(I)                            sha512_round_constants[I]
#define W(t)                            (ctx->W[t])
#define M(t)                            (ctx->M[t])
#define H(n)                            (ctx->H[n])

/**
 * SHA-384/512 logical functions
 */
#define CH(x, y, z)     (((x) & (y)) ^ ((~(x)) & (z)))
#define MAJ(x, y, z)    (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define BSIG0(x)        (u64rotr((x), 28) ^ u64rotr((x), 34) ^ u64rotr((x), 39))
#define BSIG1(x)        (u64rotr((x), 14) ^ u64rotr((x), 18) ^ u64rotr((x), 41))
#define SSIG0(x)        (u64rotr((x), 1) ^ u64rotr((x), 8) ^ u64shr((x), 7))
#define SSIG1(x)        (u64rotr((x), 19) ^ u64rotr((x), 61) ^ u64shr((x), 6))

/**
 * sha384_ctx_init() - init sha512 context with sha384 constants
 *
 * @param ctx: pointer to sha512 context
 */
void sha384_ctx_init(struct sha512_ctx *ctx)
{
        memset(ctx, 0x00, sizeof(struct sha512_ctx));

        ctx->H[0] = u64init(0xcbbb9d5d, 0xc1059ed8);
        ctx->H[1] = u64init(0x629a292a, 0x367cd507);
        ctx->H[2] = u64init(0x9159015a, 0x3070dd17);
        ctx->H[3] = u64init(0x152fecd8, 0xf70e5939);
        ctx->H[4] = u64init(0x67332667, 0xffc00b31);
        ctx->H[5] = u64init(0x8eb44a87, 0x68581511);
        ctx->H[6] = u64init(0xdb0c2e0d, 0x64f98fa7);
        ctx->H[7] = u64init(0x47b5481d, 0xbefa4fa4);
}

/**
 * sha512_ctx_init() - init sha512 context with sha512 constants
 *
 * @param ctx: pointer to sha512 context
 */
void sha512_ctx_init(struct sha512_ctx *ctx)
{
        memset(ctx, 0x00, sizeof(struct sha512_ctx));

        ctx->H[0] = u64init(0x6a09e667, 0xf3bcc908);
        ctx->H[1] = u64init(0xbb67ae85, 0x84caa73b);
        ctx->H[2] = u64init(0x3c6ef372, 0xfe94f82b);
        ctx->H[3] = u64init(0xa54ff53a, 0x5f1d36f1);
        ctx->H[4] = u64init(0x510e527f, 0xade682d1);
        ctx->H[5] = u64init(0x9b05688c, 0x2b3e6c1f);
        ctx->H[6] = u64init(0x1f83d9ab, 0xfb41bd6b);
        ctx->H[7] = u64init(0x5be0cd19, 0x137e2179);
}

static inline void __u64_cp_u8(u8 *cp, u64 v)
{
        memcpy(cp, &v, sizeof(v));
}

/**
 * sha512_ctx_read() - copy hash values to byte block
 *
 * The result must be little endian byte order
 *
 * @param ctx: pointer to sha512 context
 * @param resblk: pointer to char buffer block
 * @param bits: length of hash
 * @return resbuf
 */
void *_sha512_ctx_read(const struct sha512_ctx *ctx, void *resblk, int bits)
{
        u8 *r = resblk;
        u64 i;

        for (i = 0; i < (bits / BYTE_TO_BIT(sizeof(u64))); i++) {
#ifdef WORDS_BIGENDIAN
                __u64_cp_u8(r + i * sizeof(ctx->H[0]), u64bele(ctx->H[i]));
#else
                __u64_cp_u8(r + i * sizeof(ctx->H[0]), ctx->H[i]);
#endif
        }

        return resblk;
}

void *sha384_ctx_read(const struct sha512_ctx *ctx, void *resblk)
{
        return _sha512_ctx_read(ctx, resblk, SHA384_HASH_BITS);
}

void *sha512_ctx_read(const struct sha512_ctx *ctx, void *resblk)
{
        return _sha512_ctx_read(ctx, resblk, SHA512_HASH_BITS);
}

/**
 * sha512_ctx_prepare() - prepare variables for hash computation
 *
 * @param ctx: pointer to sha512 context
 */
void sha512_ctx_prepare(struct sha512_ctx *ctx)
{
        /*
         * For t = 0 to 15
         *    Wt = M(i)t
         */
        for (u64 t = 0; t < ARRAY_SIZE(ctx->M); ++t) {
                u64 S = ctx->M[t];

#ifndef WORD_BIGENDIAN
                /*
                 * We gonna store BE bytes into LE variable
                 * In order to make LE variable computation correct
                 * We need to convert the BE byte order to LE
                 */
                S = u64bele(S);
#endif
                memcpy(&W(t), &S, sizeof(u64));
        }

        /*
         * For t = 16 to 79
         *    Wt = SSIG1(W(t-2)) + W(t-7) + SSIG0(W(t-15)) + W(t-16)
         */
        for (u64 t = ARRAY_SIZE(ctx->M); t < ARRAY_SIZE(ctx->W); ++t) {
                W(t) = SSIG1(W(t - 2)) + W(t - 7) + SSIG0(W(t - 15)) + W(t - 16);
        }
}

/**
 * sha512_ctx_compute() - main hash algorithm
 *
 * Check out RFC6234 for details
 *
 * @param ctx: pointer to sha512 context
 */
void sha512_ctx_compute(struct sha512_ctx *ctx)
{
        u64 T1, T2;
        u64 a = H(0);
        u64 b = H(1);
        u64 c = H(2);
        u64 d = H(3);
        u64 e = H(4);
        u64 f = H(5);
        u64 g = H(6);
        u64 h = H(7);

        /*
         * Main hash computation
         *
         * For t = 0 to 79
         *    T1 = h + BSIG1(e) + CH(e,f,g) + Kt + Wt
         *    T2 = BSIG0(a) + MAJ(a,b,c)
         *     h = g
         *     g = f
         *     f = e
         *     e = d + T1
         *     d = c
         *     c = b
         *     b = a
         *     a = T1 + T2
         */
        for (u64 t = 0; t < ARRAY_SIZE(sha512_round_constants); ++t) {
                T1 = h + BSIG1(e) + CH(e, f, g) + K(t) + W(t);
                T2 = BSIG0(a) + MAJ(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
        }

        /*
         * Compute the intermediate hash value H(i)
         *
         *      next        previous
         *      -----       -------
         *      H(i)0 = a + H(i-1)0
         *        .           .
         *        .           .
         *        .           .
         *      H(i)7 = h + H(i-1)7
         */
        H(0) = a + H(0);
        H(1) = b + H(1);
        H(2) = c + H(2);
        H(3) = d + H(3);
        H(4) = e + H(4);
        H(5) = f + H(5);
        H(6) = g + H(6);
        H(7) = h + H(7);
}

/**
 * sha512_ctx_byte_counter() - count the file length in bytes
 *
 * As RFC6234 suggests, we need to compute and pad a block for
 * the *whole* message or file, so we need to count the length
 *
 * @param ctx: pointer to context
 * @param byte: size in byte
 */
void sha512_ctx_byte_counter(struct sha512_ctx *ctx, size_t byte)
{
        /*
         * Increase the byte count. Possible length of file can be up to
         * (2^128 - 1) bits. These two words consider as 128-bit int,
         * will be padded to the end of padding block.
         */
        ctx->PC[0] += byte;
        if (ctx->PC[0] < byte)
                ctx->PC[1] += 1UL;
}

/**
 * sha512_block_process() - process the data block
 *
 * Current implementation, process every 128-byte data block
 * Minimal block size for SHA384/512 to process
 *
 * @param ctx: pointer to context
 * @param buf: pointer to data block
 * @param len: length in byte of data block
 */
void sha512_block_process(struct sha512_ctx *ctx, const void *buf, size_t len)
{
        sha512_ctx_byte_counter(ctx, len);

        /* Copy 128 bytes into full M(i)n */
        memcpy(ctx->M, buf, sizeof(ctx->M));

        sha512_ctx_prepare(ctx);
        sha512_ctx_compute(ctx);
}

/**
 * sha512_bytes_process() - fill remained 128 bytes data into internal buffer
 *
 * @param ctx: pointer to context
 * @param buf: pointer to data block
 * @param len: length in byte of data block
 */
void sha512_bytes_process(struct sha512_ctx *ctx, const void *buf, size_t len)
{
        // this function handle and copy last 128 bytes data into internal buffer
        memset(ctx->buf, 0x00, sizeof(ctx->buf));
        memcpy(ctx->buf, buf, len);
        ctx->buf_len = len;
}

/**
 * sha512_ctx_conclude() - process last 128 bytes data and
 *                         compute the last padding block
 *
 * Reference: RFC6234#section-4.2
 *
 * @param ctx: pointer to context
 */
void sha512_ctx_conclude(struct sha512_ctx *ctx)
{
        /*
         * Determine the last padding block size in bytes.
         * It would be multiple of 1024-bit block,
         * depends on length of last bytes.
         */
#define MAX_L_1024BLK           ((896 - 1 - 0) / 8)
#define BLK_1024                (BIT_TO_BYTE(1024))
#define BLK_2048                (BIT_TO_BYTE(2048))

        size_t bytes = ctx->buf_len;
        size_t size = (bytes <= MAX_L_1024BLK) ? BLK_1024 : BLK_2048;
        size_t idx = size / sizeof(u64);        // align size to u64

        /* Count remained bytes */
        sha512_ctx_byte_counter(ctx, bytes);

        /* Put the 128-bit file length in *bits* at the end of padding block */
#ifdef WORDS_BIGENDIAN
        __u64_cp_u8((u8 *)&ctx->buf[idx - 2],
                    (u64or(u64shl(ctx->PC[1], 3), u64shr(ctx->PC[0], 61))));
        __u64_cp_u8((u8 *)&ctx->buf[idx - 1], (u64shl(ctx->PC[0], 3)));
#else
        __u64_cp_u8((u8 *)&ctx->buf[idx - 2],
                    u64lebe(u64or(u64shl(ctx->PC[1], 3), u64shr(ctx->PC[0], 61))));
        __u64_cp_u8((u8 *)&ctx->buf[idx - 1], u64lebe(u64shl(ctx->PC[0], 3)));
#endif

        /* Fill [1] + K[0] into padding block */
        memcpy(&((u8 *)ctx->buf)[bytes], padding_blk, (idx - 2) * 8 - bytes);

        /* Process the last padding block */
        sha512_block_process(ctx, ctx->buf, size);

#undef BLK_2048
#undef BLK_1024
#undef MAX_L_1024BLK
}

/**
 * sha512_stream_process() - hash a file
 *
 * @param stream: pointer to file
 * @param resblk: pointer to hash values block
 * @param bits: bit length of hash values
 * @return 0 on success
 */
int _sha512_stream_process(FILE *stream, void *resblk, int bits)
{
        struct sha512_ctx ctx;
        size_t len;
        int ret = 0;

        u8 *read_buf = (u8 *)malloc(PROCESS_BLOCK_SIZE + 72);
        if (!read_buf)
                return -ENOMEM;

        /* SHA384/512 use different init constants */
        if (bits == SHA384_HASH_BITS)
                sha384_ctx_init(&ctx);
        else
                sha512_ctx_init(&ctx);

        /* Iterate over whole file */
        while (1) {
                size_t n;
                len = 0;

                /* Try to read a data block */
                while (1) {
                        n = fread(read_buf + len, 1, PROCESS_BLOCK_SIZE - len, stream);
                        len += n;

                        /* We got a full block of data, gotta process */
                        if (len == PROCESS_BLOCK_SIZE)
                                break;

                        /* We read nothing in this loop, gotta check errors */
                        if (n == 0) {
                                ret = ferror(stream);
                                if (ret)
                                        goto free_buf;

                                /* No errors, hash a empty file */
                                goto process_empty_file;
                        }

                        /*
                         * At least, we read something,
                         * and always check for EOF
                         */
                        if (feof(stream))
                                goto process_partial_file;
                }

                sha512_block_process(&ctx, read_buf, len);
        }

process_partial_file:
        if (len > 0)
                sha512_bytes_process(&ctx, read_buf, len);

process_empty_file:
        sha512_ctx_conclude(&ctx);

process_hash_result:
        if (bits == SHA384_HASH_BITS)
                sha384_ctx_read(&ctx, resblk);
        else
                sha512_ctx_read(&ctx, resblk);

free_buf:
        free(read_buf);

        return ret;
}

int sha384_stream_process(FILE *stream, void *resblk)
{
        return _sha512_stream_process(stream, resblk, SHA384_HASH_BITS);
}

int sha512_stream_process(FILE *stream, void *resblk)
{
        return _sha512_stream_process(stream, resblk, SHA512_HASH_BITS);
}

/**
 * sha512_ctx_string() - convert hash result to string
 *
 * The string buffer need to be large enough
 * and allocated outside this function.
 * Output string will be processed to big-endian by sprintf().
 * Human beings use big endian.
 *
 * @param ctx: pointer to sha512 context
 * @param hash_buf: pointer to pre-allocated string buffer
 * @param bits: length of hash
 * @return hash_buf
 */
void *_sha512_ctx_string(const struct sha512_ctx *ctx, void *hash_buf, int bits)
{
        char *s = hash_buf;
        u64 i, j;

        for (i = 0, j = 0; i < (bits / BYTE_TO_BIT(sizeof(u64))); i++, j += sizeof(u64) * 2) {
                // sprintf() will handle the proper endian from memory
                sprintf(&s[j], "%016lx", ctx->H[i]);
        }

        return hash_buf;
}

void *sha384_ctx_string(const struct sha512_ctx *ctx, void *hash_buf)
{
        return _sha512_ctx_string(ctx, hash_buf, SHA384_HASH_BITS);
}

void *sha512_ctx_string(const struct sha512_ctx *ctx, void *hash_buf)
{
        return _sha512_ctx_string(ctx, hash_buf, SHA512_HASH_BITS);
}

/**
 * sha512_hash_string() - convert hash value block to string
 *
 * @param hash_blk: pointer to hash block
 * @param hash_buf: pointer to hash buffer
 * @param bits: hash value bit length
 */
void _sha512_hash_string(void *hash_blk, void *hash_buf, int bits)
{
        char *s = hash_buf;
        u64 i, j, *h;

        for (i = 0, j = 0, h = hash_blk;
             i < (bits / BYTE_TO_BIT(sizeof(u64)));
             i++, j += sizeof(u64) * 2) {
                // sprintf() will handle the proper endian from memory
                // LE -> BE, human being readable
                sprintf(&s[j], "%016lx", h[i]);
        }
}

void sha384_hash_string(void *hash_blk, void *hash_buf)
{
        return _sha512_hash_string(hash_blk, hash_buf, SHA384_HASH_BITS);
}

void sha512_hash_string(void *hash_blk, void *hash_buf)
{
        return _sha512_hash_string(hash_blk, hash_buf, SHA512_HASH_BITS);
}
