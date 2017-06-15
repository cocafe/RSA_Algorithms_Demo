/**
 * sha512.h
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

#ifndef SIMPLERSADIGEST_SHA512_H
#define SIMPLERSADIGEST_SHA512_H

/**
 * Structure stores intermediate states
 */
struct sha512_ctx {
        uint64_t        buf[32];        // Internal buffer, (32 * 64) bytes
        size_t          buf_len;        // Internal buffer length

        uint64_t        PC[2];          // Processed byte count

        uint64_t        W[80];          // Message schedule, W0 ... W79
        uint64_t        M[16];          // Message block in 64 bit, M(i)0 ... M(i)7

        uint64_t        H[8];           // Hash value, H(i)0 ... H(i)7
};

#define SHA384_HASH_BITS                (384)
#define SHA512_HASH_BITS                (512)

int sha384_stream_process(FILE *stream, void *resblk);
int sha512_stream_process(FILE *stream, void *resblk);

void *sha384_ctx_read(const struct sha512_ctx *ctx, void *resblk);
void *sha512_ctx_read(const struct sha512_ctx *ctx, void *resblk);

void *sha384_ctx_string(const struct sha512_ctx *ctx, void *hash_buf);
void *sha512_ctx_string(const struct sha512_ctx *ctx, void *hash_buf);

void sha384_hash_string(void *hash_blk, void *hash_buf);
void sha512_hash_string(void *hash_blk, void *hash_buf);

#endif //SIMPLERSADIGEST_SHA512_H
