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

#include <stdlib.h>
#include <string.h>

#include "dsa_verify.h"
#include "der.h"
#include "mp_math.h"
#include "sha1.h"

#define MP_OP(op) if ((op) != MP_OKAY) goto error;

static int _dsa_verify_hash(mp_int* hash, mp_int* keyP, mp_int* keyQ, mp_int* keyG, mp_int* keyY, mp_int* r, mp_int* s)
{
	mp_int w, v, u1, u2;
	MP_OP(mp_init_multi(&w, &v, &u1, &u2, NULL));

	// Check 0 < r < q and 0 < s < q
	if (mp_iszero(r) == MP_YES || mp_iszero(s) == MP_YES || mp_cmp(r, keyQ) != MP_LT || mp_cmp(s, keyQ) != MP_LT)
	{
		mp_clear_multi(&w, &v, &u1, &u2, NULL);
		return DSA_SIGN_PARAM_ERROR;
	}

	// w := s^-1 mod q
	MP_OP(mp_invmod(s, keyQ, &w));

	// u1 := H(m) * w mod q
	MP_OP(mp_mulmod(hash, &w, keyQ, &u1));

	// u2 := r * w mod q
	MP_OP(mp_mulmod(r, &w, keyQ, &u2));

	// v := g^u1 * y^u2 mod p mod q
	MP_OP(mp_exptmod(keyG, &u1, keyP, &u1)); // u1 := g^u1 mod p
	MP_OP(mp_exptmod(keyY, &u2, keyP, &u2)); // u2 := y^u2 mod p
	MP_OP(mp_mulmod(&u1, &u2, keyP, &v));    // v := u1 * u2 mod p
	MP_OP(mp_mod(&v, keyQ, &v));             // v := v mod q

	int ret = (mp_cmp(r, &v) == MP_EQ ? DSA_VERIFICATION_OK : DSA_VERIFICATION_FAILED);
	mp_clear_multi(&w, &v, &u1, &u2, NULL);

	return ret;

error:
	mp_clear_multi(&w, &v, &u1, &u2, NULL);
	return DSA_GENERIC_ERROR;
}

int dsa_verify_blob(const unsigned char* data, size_t data_len, const char* pubkey, const char* sig)
{
	uint8_t sha1sum[SHA1_HASH_SIZE];
	SHA1(sha1sum, data, data_len);

	return dsa_verify_hash(sha1sum, pubkey, sig);
}

int dsa_verify_hash(const uint8_t sha1[SHA1_HASH_SIZE], const char* pubkey, const char* sig)
{
	uint8_t sha1sum[SHA1_HASH_SIZE];
	SHA1(sha1sum, (const unsigned char*)sha1, SHA1_HASH_SIZE);

	size_t key_in_len = strlen(pubkey);
	size_t sig_in_len = strlen(sig);
	size_t key_len = BASE64_DECODE_OUT_SIZE(key_in_len);
	size_t sig_len = BASE64_DECODE_OUT_SIZE(sig_in_len);

	int ret;
	unsigned char* key_der = malloc(key_len);
	unsigned char* sig_der = malloc(sig_len);

	if((key_len = pem2der(pubkey, key_in_len, key_der)) == 0)
	{
		ret = DSA_KEY_FORMAT_ERROR;
		goto error;
	}

	if((sig_len = base64_decode(sig, sig_in_len, sig_der)) == 0)
	{
		ret = DSA_SIGN_FORMAT_ERROR;
		goto error;
	}

	ret = dsa_verify_hash_der(sha1sum, key_der, key_len, sig_der, sig_len);

error:
	free(key_der);
	free(sig_der);

	return ret;
}

int dsa_verify_hash_der(const uint8_t sha1[SHA1_HASH_SIZE], const unsigned char* pubkey, size_t pubkey_len, const unsigned char* sig, size_t sig_len)
{
	// Parse public key
	mp_int keyP, keyQ, keyG, keyY;
	mp_init_multi(&keyP, &keyQ, &keyG, &keyY, NULL);

	if (parse_der_pubkey(pubkey, pubkey_len, &keyP, &keyQ, &keyG, &keyY) == 0)
		return DSA_KEY_PARAM_ERROR;

	// Parse signature
	mp_int r, s;
	mp_init_multi(&r, &s, NULL);

	if (parse_der_signature(sig, sig_len, &r, &s) == 0)
		return DSA_SIGN_PARAM_ERROR;

	// Read hash, verify data
	mp_int hash;
	mp_init(&hash);
	mp_read_unsigned_bin(&hash, sha1, SHA1_HASH_SIZE);

	int ret = _dsa_verify_hash(&hash, &keyP, &keyQ, &keyG, &keyY, &r, &s);
	mp_clear_multi(&keyP, &keyQ, &keyG, &keyY, &r, &s, &hash, NULL);

	return ret;
}
