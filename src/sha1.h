/*
 *  sha1.h
 *
 *  Description:
 *      This is the header file for code which implements the Secure
 *      Hashing Algorithm 1 as defined in FIPS PUB 180-1 published
 *      April 17, 1995.
 *
 *      Many of the variable names in this code, especially the
 *      single character names, were used because those were the names
 *      used in the publication.
 *
 *      Please read the file sha1.c for more information.
 *
 */

#ifndef __SHA1_H__
#define __SHA1_H__

#include <stdint.h>

/*
 * If you do not have the ISO standard stdint.h header file, then you
 * must typdef the following:
 *    name              meaning
 *  uint32_t         unsigned 32 bit integer
 *  uint8_t          unsigned 8 bit integer (i.e., unsigned char)
 *  int_least16_t    integer of >= 16 bits
 *
 */

enum
{
    SHA_SUCCESS = 0,    ///< Hash was successful
    SHA_NULL,           ///< NULL pointer parameter
    SHA_INPUT_TOO_LONG, ///< Input data too long
    SHA_STATE_ERROR     ///< Called Input after Result
};

/** @brief Size of a SHA1 hash, in bytes */
#define SHA1_HASH_SIZE 20

/*
 *  This structure will hold context information for the SHA-1
 *  hashing operation
 */
typedef struct SHA1Context
{
    uint32_t Intermediate_Hash[SHA1_HASH_SIZE / 4]; /* Message Digest  */

    uint32_t Length_Low;            /* Message length in bits      */
    uint32_t Length_High;           /* Message length in bits      */

                               /* Index into message block array   */
    int_least16_t Message_Block_Index;
    uint8_t Message_Block[64];      /* 512-bit message blocks      */

    int Computed;              /* Is the digest computed?         */
    int Corrupted;             /* Is the message digest corrupted? */
} SHA1Context;

/*
 *  Function Prototypes
 */

/** @brief Reset SHA1 state */
int SHA1_reset(SHA1Context*);

/** @brief Compute hash of given data */
int SHA1_input(SHA1Context*, const uint8_t* message_array, unsigned int len);

/**
 * @brief Get SHA1 hash of the computed data.
 *
 * Returns the hash using the second parameter. Internal state is invalid after
 * this function is called.
 *
 * @returns @ref SHA_SUCCESS on success, otherwise it returns any of @ref
 * SHA_NULL, @ref SHA_INPUT_TOO_LONG or @ref SHA_STATE_ERROR.
 */
int SHA1_result(SHA1Context*, uint8_t message_digest[SHA1_HASH_SIZE]);

#endif
