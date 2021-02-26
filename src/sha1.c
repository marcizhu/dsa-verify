/*
 *  sha1.c
 *
 *  Description:
 *      This file implements the Secure Hashing Algorithm 1 as
 *      defined in FIPS PUB 180-1 published April 17, 1995.
 *
 *      The SHA-1, produces a 160-bit message digest for a given
 *      data stream.  It should take about 2**n steps to find a
 *      message with the same digest as a given message and
 *      2**(n/2) to find any two messages with the same digest,
 *      when n is the digest size in bits.  Therefore, this
 *      algorithm can serve as a means of providing a
 *      "fingerprint" for a message.
 *
 *  Portability Issues:
 *      SHA-1 is defined in terms of 32-bit "words".  This code
 *      uses <stdint.h> (included via "sha1.h" to define 32 and 8
 *      bit unsigned integer types.  If your C compiler does not
 *      support 32 bit unsigned integers, this code is not
 *      appropriate.
 *
 *  Caveats:
 *      SHA-1 is designed to work with messages less than 2^64 bits
 *      long.  Although SHA-1 allows a message digest to be generated
 *      for messages of any number of bits less than 2^64, this
 *      implementation only works with messages with a length that is
 *      a multiple of the size of an 8-bit character.
 *
 */

#include "sha1.h"

/*
 *  Define the SHA1 circular left shift macro
 */
#define SHA1_circular_shift(bits, word) \
	(((word) << (bits)) | ((word) >> (32 - (bits))))

/* Local Function Prototyptes */
void SHA1_pad_message(SHA1Context*);
void SHA1_process_message_block(SHA1Context*);

/*
 *  SHA1Reset
 *
 *  Description:
 *      This function will initialize the SHA1Context in preparation
 *      for computing a new SHA1 message digest.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to reset.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1_reset(SHA1Context* context)
{
	if (!context)
		return SHA_NULL;

	context->Length_Low           = 0;
	context->Length_High          = 0;
	context->Message_Block_Index  = 0;

	context->Intermediate_Hash[0] = 0x67452301;
	context->Intermediate_Hash[1] = 0xEFCDAB89;
	context->Intermediate_Hash[2] = 0x98BADCFE;
	context->Intermediate_Hash[3] = 0x10325476;
	context->Intermediate_Hash[4] = 0xC3D2E1F0;

	context->Computed  = 0;
	context->Corrupted = 0;

	return SHA_SUCCESS;
}

/*
 *  SHA1Result
 *
 *  Description:
 *      This function will return the 160-bit message digest into the
 *      Message_Digest array  provided by the caller.
 *      NOTE: The first octet of hash is stored in the 0th element,
 *            the last octet of hash in the 19th element.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to use to calculate the SHA-1 hash.
 *      Message_Digest: [out]
 *          Where the digest is returned.
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1_result(SHA1Context* context, uint8_t message_digest[SHA1_HASH_SIZE])
{
	if (!context || !message_digest)
		return SHA_NULL;

	if (context->Corrupted)
		return context->Corrupted;

	if (!context->Computed)
	{
		SHA1_pad_message(context);

		for(int i = 0; i < 64; ++i)
		{
			/* message may be sensitive, clear it out */
			context->Message_Block[i] = 0;
		}

		context->Length_Low = 0;    /* and clear length */
		context->Length_High = 0;
		context->Computed = 1;
	}

	for(int i = 0; i < SHA1_HASH_SIZE; ++i)
	{
		message_digest[i] = context->Intermediate_Hash[i >> 2] >> 8 * (3 - (i & 0x03));
	}

	return SHA_SUCCESS;
}

/*
 *  SHA1Input
 *
 *  Description:
 *      This function accepts an array of octets as the next portion
 *      of the message.
 *
 *  Parameters:
 *      context: [in/out]
 *          The SHA context to update
 *      message_array: [in]
 *          An array of characters representing the next portion of
 *          the message.
 *      length: [in]
 *          The length of the message in message_array
 *
 *  Returns:
 *      sha Error Code.
 *
 */
int SHA1_input(SHA1Context* context, const uint8_t* message_array, unsigned len)
{
//	if (!len)
//		return SHA_SUCCESS;

	if (!context || !message_array)
		return SHA_NULL;

	if (context->Computed)
	{
		context->Corrupted = SHA_STATE_ERROR;
		return SHA_STATE_ERROR;
	}

	if (context->Corrupted)
		 return context->Corrupted;

	while(len-- && !context->Corrupted)
	{
		context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);
		context->Length_Low += 8;

		if (context->Length_Low == 0)
		{
			context->Length_High++;
			if (context->Length_High == 0)
			{
				/* Message is too long */
				context->Corrupted = 1;
				return SHA_INPUT_TOO_LONG;
			}
		}

		if (context->Message_Block_Index == 64)
			SHA1_process_message_block(context);

		message_array++;
	}

	return SHA_SUCCESS;
}

/*
 *  SHA1ProcessMessageBlock
 *
 *  Description:
 *      This function will process the next 512 bits of the message
 *      stored in the Message_Block array.
 *
 *  Parameters:
 *      None.
 *
 *  Returns:
 *      Nothing.
 *
 *  Comments:

 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the
 *      names used in the publication.
 *
 *
 */
void SHA1_process_message_block(SHA1Context* context)
{
	/* Constants defined in SHA-1   */
	const uint32_t K[] = { 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6 };

//	int           t;                 /* Loop counter                */
//	uint32_t      temp;              /* Temporary word value        */
	uint32_t      W[80];             /* Word sequence               */
//	uint32_t      A, B, C, D, E;     /* Word buffers                */

	/*
	 *  Initialize the first 16 words in the array W
	 */
	for(int i = 0; i < 16; i++)
	{
		W[i]  = context->Message_Block[i * 4 + 0] << 24;
		W[i] |= context->Message_Block[i * 4 + 1] << 16;
		W[i] |= context->Message_Block[i * 4 + 2] <<  8;
		W[i] |= context->Message_Block[i * 4 + 3] <<  0;
	}

	for(int i = 16; i < 80; i++)
	{
		W[i] = SHA1_circular_shift(1, W[i - 3] ^ W[i - 8] ^ W[i - 14] ^ W[i - 16]);
	}

	uint32_t A = context->Intermediate_Hash[0];
	uint32_t B = context->Intermediate_Hash[1];
	uint32_t C = context->Intermediate_Hash[2];
	uint32_t D = context->Intermediate_Hash[3];
	uint32_t E = context->Intermediate_Hash[4];

	for(int i = 0; i < 20; i++)
	{
		uint32_t temp = SHA1_circular_shift(5, A) + ((B & C) | ((~B) & D)) + E + W[i] + K[0];

		E = D;
		D = C;
		C = SHA1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	for(int i = 20; i < 40; i++)
	{
		uint32_t temp = SHA1_circular_shift(5, A) + (B ^ C ^ D) + E + W[i] + K[1];
		E = D;
		D = C;
		C = SHA1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	for(int i = 40; i < 60; i++)
	{
		uint32_t temp = SHA1_circular_shift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[i] + K[2];

		E = D;
		D = C;
		C = SHA1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	for(int i = 60; i < 80; i++)
	{
		uint32_t temp = SHA1_circular_shift(5, A) + (B ^ C ^ D) + E + W[i] + K[3];

		E = D;
		D = C;
		C = SHA1_circular_shift(30, B);
		B = A;
		A = temp;
	}

	context->Intermediate_Hash[0] += A;
	context->Intermediate_Hash[1] += B;
	context->Intermediate_Hash[2] += C;
	context->Intermediate_Hash[3] += D;
	context->Intermediate_Hash[4] += E;

	context->Message_Block_Index = 0;
}

/*
 *  SHA1PadMessage
 *

 *  Description:
 *      According to the standard, the message must be padded to an even
 *      512 bits.  The first padding bit must be a '1'.  The last 64
 *      bits represent the length of the original message.  All bits in
 *      between should be 0.  This function will pad the message
 *      according to those rules by filling the Message_Block array
 *      accordingly.  It will also call the ProcessMessageBlock function
 *      provided appropriately.  When it returns, it can be assumed that
 *      the message digest has been computed.
 *
 *  Parameters:
 *      context: [in/out]
 *          The context to pad
 *      ProcessMessageBlock: [in]
 *          The appropriate SHA*ProcessMessageBlock function
 *  Returns:
 *      Nothing.
 *
 */

void SHA1_pad_message(SHA1Context* context)
{
	/*
	 *  Check to see if the current message block is too small to hold
	 *  the initial padding bits and length.  If so, we will pad the
	 *  block, process it, and then continue padding into a second
	 *  block.
	 */
	context->Message_Block[context->Message_Block_Index++] = 0x80;

	if (context->Message_Block_Index > 55)
	{
		while(context->Message_Block_Index < 64)
		{
			context->Message_Block[context->Message_Block_Index++] = 0;
		}

		SHA1_process_message_block(context);
	}

	while(context->Message_Block_Index < 56)
	{
		context->Message_Block[context->Message_Block_Index++] = 0;
	}

	//  Store the message length as the last 8 octets
	context->Message_Block[56] = context->Length_High >> 24;
	context->Message_Block[57] = context->Length_High >> 16;
	context->Message_Block[58] = context->Length_High >> 8;
	context->Message_Block[59] = context->Length_High;
	context->Message_Block[60] = context->Length_Low >> 24;
	context->Message_Block[61] = context->Length_Low >> 16;
	context->Message_Block[62] = context->Length_Low >> 8;
	context->Message_Block[63] = context->Length_Low;

	SHA1_process_message_block(context);
}
