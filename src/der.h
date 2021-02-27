/*
 *  This file is part of the dsa-verify library (https://github.com/marcizhu/dsa-verify)
 *
 *  Copyright (C) 2021 Marc Izquierdo
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a
 *  copy of this software and associated documentation files (the "Software"),
 *  to deal in the Software without restriction, including without limitation
 *  the rights to use, copy, modify, merge, publish, distribute, sublicense,
 *  and/or sell copies of the Software, and to permit persons to whom the
 *  Software is furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in
 *  all copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 *  FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 *  DEALINGS IN THE SOFTWARE.
 *
 */

#ifndef _PEM2DER_
#define _PEM2DER_

#include <stddef.h>

#include "mp_math.h"

/** @brief Returns an upper bound of the number of bytes used by a base-64 encoded string */
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
 * @param[in]  pem  Null-terminated with PEM-encoded key data
 * @param[in]  len  Length of the null-terminated string
 * @param[out] out  Where to store the DER data. It should be at least
 *                  `BASE64_DECODE_OUT_SIZE(len)` bytes long.
 *
 * @returns 0 on error, otherwise returns the number of bytes the DER encoding
 * uses.
 */
size_t pem2der(const char* pem, size_t len, unsigned char* out);

#endif
