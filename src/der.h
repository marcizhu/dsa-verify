#ifndef _PEM2DER_
#define _PEM2DER_

#include <stddef.h>

#include "mp_math.h"

#define BASE64_DECODE_OUT_SIZE(s)  ((unsigned int)(((s) / 4) * 3))

size_t base64_decode(const char* in, size_t inlen, unsigned char* out);

int parse_der_pubkey(const unsigned char* der, size_t len, mp_int* keyP, mp_int* keyQ, mp_int* keyG, mp_int* keyY);

int parse_der_signature(const unsigned char* der, size_t len, mp_int* r, mp_int* s);

/**
 * @brief Parses a PEM file, removed the armoring and returns DER-encoded data
 *
 * This function accepts a standard PEM public/private key file, strips the
 * "-----BEGIN..." and "-----END..." lines, base64-decodes its contents and
 * returns that.
 *
 * @param pem  Null-terminated with PEM-encoded key data
 * @param len  Length of the null-terminated string
 * @param out  Where to store the DER data. It should be at least
 *             `BASE64_DECODE_OUT_SIZE(len)` bytes long.
 *
 * @returns 0 on error, otherwise returns the number of bytes the DER encoding
 * uses.
 */
size_t pem2der(const char* pem, size_t len, unsigned char* out);

#endif
