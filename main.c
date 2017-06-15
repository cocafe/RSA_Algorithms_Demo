/**
 * main.c - Demo of RSA signature process
 *
 *      Author: cocafe <cocafehj@gmail.com> 2016
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
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>

#include "rsa.h"
#include "sha512.h"

#define RSA_KEY_LENGTH                          (2048)
#if RSA_KEY_LENGTH % 2
#error invalid rsa key length
#endif

#define RSA_PUBLIC_KEY                          "pub.key"
#define RSA_PRIVATE_KEY                         "priv.key"
#define PLAIN_MESSAGE                           "msg.txt"
#define MSG_DIGEST_ALICE                        "sha512_alice.txt"
#define MSG_DIGEST_BOB                          "sha512_bob.txt"
#define MSG_SIGN_ENCRYPTED                      "sign_encrypted.txt"
#define MSG_SIGN_DECYRPTED                      "sign_decrypted.txt"

struct rsa_public  public_key;
struct rsa_private private_key;

/* Not implemented, demo functions */
static inline void des_encrypt(void) { }
static inline void des_decrypt(void) { }

// FIXME: ignored releasing resources after failures
int demo(uint32_t key_length)
{
        uint8_t hash[SHA512_HASH_BITS / 8];
        char hash_str[SHA512_HASH_BITS / 4];

        char hash_decrypt[(SHA512_HASH_BITS / 4) + 1];
        char hash_str_bob[(SHA512_HASH_BITS / 4) + 1];

        int ret = EXIT_SUCCESS;

        FILE *msg_plain;
        FILE *sign_encrypt;
        FILE *sign_decrypt;
        FILE *key_pub;
        FILE *key_priv;
        FILE *hash_alice;
        FILE *hash_bob;

        if (key_length % 2)
                key_length = RSA_KEY_LENGTH;

        rsa_public_key_init(&public_key);
        rsa_private_key_init(&private_key);

        /**
         * Alice: generates and saves her RSA key pair
         */

        fprintf(stdout, "Alice: generating %u-bit RSA Key pair...\n", key_length);

        if (rsa_private_key_generate(&private_key, key_length))
                return 1;

        if (rsa_public_key_generate(&public_key, &private_key))
                return 1;

        key_priv = fopen(RSA_PRIVATE_KEY, "w");
        if (!key_priv)
                return 1;

        key_pub = fopen(RSA_PUBLIC_KEY, "w");
        if (!key_pub)
                return 1;

        fprintf(stdout, "Alice RSA private key:\n");
        rsa_private_key_dump(&private_key, stdout);

        fprintf(stdout, "\nAlice RSA public key:\n");
        rsa_public_key_dump(&public_key, stdout);

        rsa_public_key_save(&public_key, key_pub);
        rsa_private_key_save(&private_key, key_priv);

        fflush(key_priv);
        fflush(key_pub);
        fclose(key_priv);
        fclose(key_pub);

        /**
         * Alice: uses sha512sum to generate her message digest
         */

        msg_plain = fopen(PLAIN_MESSAGE, "r");
        if (!msg_plain)
                return 1;

        memset(hash, 0x00, sizeof(hash));
        memset(hash_str, 0x00, sizeof(hash_str));

        sha512_stream_process(msg_plain, hash);
        sha512_hash_string(hash, hash_str);

        hash_alice = fopen(MSG_DIGEST_ALICE, "w");
        if (!hash_alice)
                return 1;

        fprintf(stdout, "\nAlice: sha512sum: %s %s\n", hash_str, PLAIN_MESSAGE);

        fprintf(hash_alice, "%s\n", hash_str);

        fflush(hash_alice);
        fclose(hash_alice);
        fclose(msg_plain);

        /**
         * Signature
         *
         * Alice: encrypt message digest with RSA private key, block type 01
         */

        sign_encrypt = fopen(MSG_SIGN_ENCRYPTED, "w");
        if (!sign_encrypt)
                return 1;

        hash_alice = fopen(MSG_DIGEST_ALICE, "r");
        if (!hash_alice)
                return 1;

        fprintf(stdout, "\nAlice encrypting signature with private key:\n");

        rsa_private_key_encrypt(&private_key, sign_encrypt, hash_alice);

        fclose(hash_alice);
        fflush(sign_encrypt);
        fclose(sign_encrypt);

        /**
         * Alice:
         * use other method to encrypted plain message,
         * transfer with digital signature
         */

        des_encrypt();

        /**
         * Organize other information, transfer encrypted message to Bob
         */

        fprintf(stdout, "\nAlice: Transferred encrypted message with signature\n");
        fprintf(stdout, "\nBob: Received encrypted message with signature\n");

        /**
         * Bob: decrypted message
         */

        des_decrypt();

        /**
         * Bob: decrypted signature with Alice's RSA public key, gets message digest
         */

        fprintf(stdout, "\nBob: Decrypting signature with Alice\'s RSA public key\n");

        sign_encrypt = fopen(MSG_SIGN_ENCRYPTED, "r");
        if (!sign_encrypt)
                return 1;

        sign_decrypt = fopen(MSG_SIGN_DECYRPTED, "w");
        if (!sign_decrypt)
                return 1;

        rsa_public_key_decrypt(&public_key, sign_decrypt, sign_encrypt);

        fflush(sign_decrypt);
        fclose(sign_decrypt);
        fclose(sign_encrypt);

        /**
         * Bob: hashes decrypted plain text with sha512sum
         */

        fprintf(stdout, "\nBob: Hashing decrypted plain message\n");

        msg_plain = fopen(PLAIN_MESSAGE, "r");
        if (!msg_plain)
                return 1;

        hash_bob = fopen(MSG_DIGEST_BOB, "w");
        if (!hash_bob)
                return 1;

        memset(hash, 0x00, sizeof(hash));
        memset(hash_str, 0x00, sizeof(hash_str));

        sha512_stream_process(msg_plain, &hash);
        sha512_hash_string(hash, hash_str);

        fprintf(stdout, "\nBob: sha512sum: %s %s\n", hash_str, PLAIN_MESSAGE);

        fprintf(hash_bob, "%s\n", hash_str);

        fflush(hash_bob);
        fclose(hash_bob);
        fclose(msg_plain);

        /**
         * Signature Verification
         *
         * Bob: compare decrypted plain text hash with hash in decrypted message digest
         */

        fprintf(stdout, "\nBob: Comparing decrypted signature with transferred message\'s hash\n");

        sign_decrypt = fopen(MSG_SIGN_DECYRPTED, "r");
        if (!sign_decrypt)
                return 1;

        hash_bob = fopen(MSG_DIGEST_BOB, "r");
        if (!hash_bob)
                return 1;

        memset(hash_str_bob, 0x00, sizeof(hash_str_bob));
        memset(hash_decrypt, 0x00, sizeof(hash_decrypt));

        fscanf(hash_bob, "%s", hash_str_bob);
        fscanf(sign_decrypt, "%s", hash_decrypt);

        fprintf(stdout, "\nDecrypted signature:   %s\n", hash_decrypt);
        fprintf(stdout,   "Received message hash: %s\n", hash_str_bob);

        if (!strncmp(hash_str_bob, hash_decrypt, SHA512_HASH_BITS / 8))
                fprintf(stderr, "\nDecrypted signature sha512 hash matched!\n");
        else
                fprintf(stderr, "\nDecrypted signature sha512 hash does not match!\n");

        fclose(hash_bob);
        fclose(sign_decrypt);

        rsa_public_key_clean(&public_key);
        rsa_private_key_clean(&private_key);

        return ret;
}

int main(int argc, char *argv[])
{
        uint32_t key_length = RSA_KEY_LENGTH;

        if (argc == 2)
                sscanf(argv[2 - 1], "%u", &key_length);

        return demo(key_length);
}