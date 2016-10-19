#include <stdio.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/evp.h>

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
              u_int8_t * text, u_int32_t textlen);

/*
int
main(void)
{
    char            key[]   = "6dbf2a50d46a5852cd2d63f6f2707cfc";
    char            data[]  = "http://www.mosalov.com";
    char            digest[41];

    hmac_sha1_hex(digest, key, strlen(key), data, strlen(data));

    printf("HMAC-SHA1 = %s\n", digest);
};
*/
