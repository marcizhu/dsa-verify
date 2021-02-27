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

#include <stddef.h>
#include <string.h>

#include "der.h"

#define BASE64_PAD '='

/* ASCII order for BASE 64 decode, 255 in unused character */
static const unsigned char base64de[] =
{
	/* nul, soh, stx, etx, eot, enq, ack, bel, */
	   255, 255, 255, 255, 255, 255, 255, 255,
	/*  bs,  ht,  nl,  vt,  np,  cr,  so,  si, */
	   255, 255, 255, 255, 255, 255, 255, 255,
	/* dle, dc1, dc2, dc3, dc4, nak, syn, etb, */
	   255, 255, 255, 255, 255, 255, 255, 255,
	/* can,  em, sub, esc,  fs,  gs,  rs,  us, */
	   255, 255, 255, 255, 255, 255, 255, 255,
	/*  sp, '!', '"', '#', '$', '%', '&', ''', */
	   255, 255, 255, 255, 255, 255, 255, 255,
	/* '(', ')', '*', '+', ',', '-', '.', '/', */
	   255, 255, 255,  62, 255, 255, 255,  63,
	/* '0', '1', '2', '3', '4', '5', '6', '7', */
		52,  53,  54,  55,  56,  57,  58,  59,
	/* '8', '9', ':', ';', '<', '=', '>', '?', */
		60,  61, 255, 255, 255, 255, 255, 255,
	/* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', */
	   255,   0,   1,  2,   3,   4,   5,    6,
	/* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', */
		 7,   8,   9,  10,  11,  12,  13,  14,
	/* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', */
		15,  16,  17,  18,  19,  20,  21,  22,
	/* 'X', 'Y', 'Z', '[', '\', ']', '^', '_', */
		23,  24,  25, 255, 255, 255, 255, 255,
	/* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', */
	   255,  26,  27,  28,  29,  30,  31,  32,
	/* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', */
		33,  34,  35,  36,  37,  38,  39,  40,
	/* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', */
		41,  42,  43,  44,  45,  46,  47,  48,
	/* 'x', 'y', 'z', '{', '|', '}', '~', del, */
		49,  50,  51, 255, 255, 255, 255, 255
};

size_t base64_decode(const char* in, size_t inlen, unsigned char* out)
{
	size_t j = 0;
	size_t ignored = 0;

	for (size_t i = 0; i < inlen; i++)
	{
		if (in[i] == BASE64_PAD)
			break;

		if (in[i] == '\n' || in[i] == '\r' || in[i] == '\t' || in[i] == ' ')
		{
			ignored++;
			continue;
		}

		unsigned char c = base64de[(unsigned char)in[i]];

		if (c == 255)
			return 0;

		switch((i - ignored) & 0x3)
		{
			case 0:
				out[j] = (c << 2) & 0xFF;
				break;
			case 1:
				out[j++] |= (c >> 4) & 0x3;
				out[j] = (c & 0xF) << 4; 
				break;
			case 2:
				out[j++] |= (c >> 2) & 0xF;
				out[j] = (c & 0x3) << 6;
				break;
			case 3:
				out[j++] |= c;
				break;
		}
	}

	return j;
}

// This function modifies the input pointer & size so that it points to the
// actual contents of the file, aka it skips the "---- BEGIN..." and the
// "----- END..." sections of the key. Also it skips newlines and text before
// the begin clause, therefore comments are somewhat allowed
static int dearmor(const char** pem, size_t* len)
{
	if(!pem || !len)
		return 0;

	for(size_t i = 0; i < *len; i++)
	{
		if (((*pem)[i] == '\n') || ((*pem)[i] == '\r'))
			continue;

		if ((*pem)[i] != '-')
		{
			// read entire line
			while ((i < *len) && ((*pem)[i] != '\n'))
				i++;

			continue;
		}

		if ((*pem)[i] == '-')
		{
			//read until end of line
			while ((i < *len) && ((*pem)[i] != '\n'))
				i++;

			size_t begin = i;

			while ((i < *len) && ((*pem)[i] != '-'))
				i++;

			size_t end = i;

			*len = end - begin;
			*pem = *pem + begin;
		}
	}

	return 1;
}

enum ASN1_Type
{
	ASN1_Type_EOC               =  0,
	ASN1_Type_BOOLEAN           =  1,
	ASN1_Type_INTEGER           =  2,
	ASN1_Type_BIT_STRING        =  3,
	ASN1_Type_OCTET_STRING      =  4,
	ASN1_Type_NULL              =  5,
	ASN1_Type_OBJECT_IDENTIFIER =  6,
	ASN1_Type_OBJECT_DESCRIPTOR =  7,
	ASN1_Type_EXTERNAL          =  8,
	ASN1_Type_REAL              =  9,
	ASN1_Type_ENUMERATED        = 10,
	ASN1_Type_EMBEDDED_PDV      = 11,
	ASN1_Type_UTF8_STRING       = 12,
	ASN1_Type_RELATIVE_OID      = 13,
	ASN1_Type_TIME              = 14,
	ASN1_Type_RESERVED_         = 15,
	ASN1_Type_SEQUENCE          = 16,
	ASN1_Type_SET               = 17,
	ASN1_Type_NUMERIC_STRING    = 18,
	ASN1_Type_PRINTABLE_STRING  = 19,
	ASN1_Type_T61STRING         = 20,
	ASN1_Type_VIDEOTEX_STRING   = 21,
	ASN1_Type_IA5STRING         = 22,
	ASN1_Type_UTC_TIME          = 23,
	ASN1_Type_GENERALIZED_TIME  = 24,
	ASN1_Type_GRAPHIC_STRING    = 25,
	ASN1_Type_VISIBLE_STRING    = 26,
	ASN1_Type_GENERAL_STRING    = 27,
	ASN1_Type_UNIVERSAL_STRING  = 28,
	ASN1_Type_CHARACTER_STRING  = 29,
	ASN1_Type_BMP_STRING        = 30,
	ASN1_Type_DATE              = 31,
	ASN1_Type_TIME_OF_DAY       = 32,
	ASN1_Type_DATE_TIME         = 33,
	ASN1_Type_DURATION          = 34,
	ASN1_Type_OID_IRI           = 35,
	ASN1_Type_RELATIVE_OID_IRI  = 36,
};

static size_t _parse_length(const unsigned char** der)
{
	if(((**der & 0x80) >> 7) == 0)
	{
		(*der) += 1;
		return ((*der)[-1] & ~0x80);
	}

	else
	{
		unsigned int bytes = (*(*der)++ & ~0x80);
		size_t ret = 0;

		for(unsigned int i = 0; i < bytes; i++)
			ret = (ret << 8) | *(*der)++;

		return ret;
	}

	return 0;
}

#define ASN1_TAG_CONSTRUCTED(x)  ((int)((x >> 5) & 0x01))
#define ASN1_TAG_NUMBER(x)       ((unsigned int)((x >> 0) & 0x1F))

#define SEQUENCE          if(ASN1_TAG_CONSTRUCTED(*der) == 1 && ASN1_TAG_NUMBER(*der) == ASN1_Type_SEQUENCE)
#define INTEGER           if(ASN1_TAG_CONSTRUCTED(*der) == 0 && ASN1_TAG_NUMBER(*der) == ASN1_Type_INTEGER)
#define OBJECT_IDENTIFIER if(ASN1_TAG_CONSTRUCTED(*der) == 0 && ASN1_TAG_NUMBER(*der) == ASN1_Type_OBJECT_IDENTIFIER)
#define BIT_STRING        if(ASN1_TAG_CONSTRUCTED(*der) == 0 && ASN1_TAG_NUMBER(*der) == ASN1_Type_BIT_STRING)

int parse_der_pubkey(const unsigned char* der, size_t len, mp_int* keyP, mp_int* keyQ, mp_int* keyG, mp_int* keyY)
{
	static unsigned char ansi_x9_57[] = { 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01 };
	const unsigned char* end = der + len;

	SEQUENCE
	{
		if ((++der + _parse_length(&der)) > end)
			return 0;

		SEQUENCE
		{
			if ((++der + _parse_length(&der)) > end)
				return 0;

			OBJECT_IDENTIFIER
			{
				der++;
				size_t length = _parse_length(&der);

				if (length == sizeof(ansi_x9_57) && memcmp(der, ansi_x9_57, length) != 0)
					return 0;

				der += length;
			}

			SEQUENCE
			{
				if ((++der + _parse_length(&der)) > end)
					return 0;

				INTEGER
				{
					// p
					der++;
					size_t length = _parse_length(&der);

					if ((der + length) > end)
						return 0;

					if (mp_read_unsigned_bin(keyP, der, length) != MP_OKAY)
						return 0;

					der += length;
				}

				INTEGER
				{
					// q
					der++;
					size_t length = _parse_length(&der);

					if ((der + length) > end)
						return 0;

					if (mp_read_unsigned_bin(keyQ, der, length) != MP_OKAY)
						return 0;

					der += length;
				}

				INTEGER
				{
					// g
					der++;
					size_t length = _parse_length(&der);

					if ((der + length) > end)
						return 0;

					if (mp_read_unsigned_bin(keyG, der, length) != MP_OKAY)
						return 0;

					der += length;
				}
			}
		}

		BIT_STRING
		{
			if ((++der + _parse_length(&der)) > end)
				return 0;

			if (*der++ != 0)
				return 0;

			INTEGER
			{
				// y
				der++;
				size_t length = _parse_length(&der);

				if ((der + length) > end)
					return 0;

				return (mp_read_unsigned_bin(keyY, der, length) == MP_OKAY);
			}
		}
	}

	return 0;
}

int parse_der_signature(const unsigned char* der, size_t len, mp_int* r, mp_int* s)
{
	const unsigned char* end = der + len;

	SEQUENCE
	{
		if((++der + _parse_length(&der)) > end)
			return 0;

		INTEGER
		{
			// r
			der++;
			size_t length = _parse_length(&der);

			if ((der + length) > end)
				return 0;

			if (mp_read_unsigned_bin(r, der, length) != MP_OKAY)
				return 0;

			der += length;
		}

		INTEGER
		{
			// s
			der++;
			size_t length = _parse_length(&der);

			if((der + length) > end)
				return 0;

			return (mp_read_unsigned_bin(s, der, length) == MP_OKAY);
		}
	}

	return 0;
}

size_t pem2der(const char* pem, size_t len, unsigned char* out)
{
	const char* begin = pem;
	size_t pem_len = len;

	if(dearmor(&begin, &pem_len) == 0)
		return 0;

	return base64_decode(begin, pem_len, (unsigned char*)out);
}
