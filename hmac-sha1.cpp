#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include "hmac-sha1.h"

/*
 * Compile:
 *
 * gcc -o hmac-sha1 hmac-sha1.c -lssl
 *
 * References:
 *
 * http://www.koders.com/c/fidCB5D80A85E472608D96B0F9DC3128E6821AA8E70.aspx
 * http://developer.apple.com/DOCUMENTATION/Darwin/Reference/ManPages/man3/SHA1_Final.3ssl.html
 * http://tools.ietf.org/html/rfc2202
 */

void
hmac_sha1_hex(u_int8_t * digest, u_int8_t * key, u_int32_t keylen,
              u_int8_t * text, u_int32_t textlen)
{
    u_int8_t        md[20];
    u_int8_t        mdkey[20];
    u_int8_t        k_ipad[64],
                    k_opad[64];
    unsigned int    i;
    char            s[3];

    if (keylen > 64) {
        SHA_CTX         ctx;

        SHA1_Init(&ctx);
        SHA1_Update(&ctx, key, keylen);
        SHA1_Final(mdkey, &ctx);
        keylen = 20;

        key = mdkey;
    }

    memcpy(k_ipad, key, keylen);
    memcpy(k_opad, key, keylen);
    memset(k_ipad + keylen, 0, 64 - keylen);
    memset(k_opad + keylen, 0, 64 - keylen);

    for (i = 0; i < 64; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    SHA_CTX         ctx;

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, k_ipad, 64);
    SHA1_Update(&ctx, text, textlen);
    SHA1_Final(md, &ctx);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, k_opad, 64);
    SHA1_Update(&ctx, md, 20);
    SHA1_Final(md, &ctx);

    for (i = 0; i < 20; i++) {
        snprintf(s, 3, "%02x", md[i]);
        digest[2 * i] = s[0];
        digest[2 * i + 1] = s[1];
    }

    digest[40] = '\0';
}

/*int
main(void)
{
    char            key[]   = "6dbf2a50d46a5852cd2d63f6f2707cfc";
    char            data[]  = "http://www.mosalov.com";
    char            digest[41];

    hmac_sha1_hex(digest, key, strlen(key), data, strlen(data));

    printf("HMAC-SHA1 = %s\n", digest);
};
*/
