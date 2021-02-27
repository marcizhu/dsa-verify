/*
SHA-1 in C
By Steve Reid <steve@edmweb.com>
100% Public Domain
*/

#ifndef __SHA1_H__
#define __SHA1_H__

#include <stdint.h>

/** @brief SHA1 context */
typedef struct
{
    uint32_t state[5];
    uint32_t count[2];
    unsigned char buffer[64];
} SHA1_CTX;

/** @brief SHA1 hash size, in bytes */
#define SHA1_HASH_SIZE 20

/**
 * @brief Reset SHA1 context
 *
 * Resets the given SHA1 context, setting it to a default state. This function
 * can be called at any time, and thus allows to reuse the same context to
 * calculate many SHA1 hashes.
 *
 * @param[in,out] context  SHA1 context
 */
void SHA1_reset(SHA1_CTX* context);

/**
 * @brief Feed data to SHA1 hash
 *
 * This function takes some data and processes it to calculate the SHA1 hash.
 * This function *MUST* be called after a call to @ref SHA1_reset(), and it
 * can be called as many times as necessary in order to feed all the data the
 * user wants. Once all data has been fed, call @ref SHA1_result() to get the
 * final hash value.
 *
 * @param[in,out] context  SHA1 context
 * @param[in]     data     Data to be fed to the algorithm
 * @param[in]     len      Length of the data to be fed
 */
void SHA1_input(SHA1_CTX* context, const unsigned char* data, uint32_t len);

/**
 * @brief Get the SHA1 hash of the previously-fed data
 *
 * Generates the SHA1 hash based on the data fed previously using the function
 * @ref SHA1_input(). This function leaves the context in an invalid state. Thus,
 * in order to reuse the same context it is necessary to call @ref SHA1_reset().
 * If no more hashes are desired, the context can be left as is, no cleanup is
 * necessary.
 *
 * @param[in,out] context  SHA1 context
 * @param[out]    digest   SHA1 hash output
 */
void SHA1_result(SHA1_CTX* context, uint8_t digest[SHA1_HASH_SIZE]);

/**
 * @brief Calculate SHA1 of given data
 *
 * Calculates the SHA1 hash of the given data, without the need to create and
 * initialize the SHA1 context. Useful to hash a single block of data at once.
 *
 * @param[out] digest  Array where the SHA1 hash will be stored
 * @param[in]  data    Byte-array of the data to be hashed
 * @param[in]  len     Length of the byte-array of data, in bytes.
 */
void SHA1(uint8_t digest[SHA1_HASH_SIZE], const unsigned char* data, uint32_t len);

#endif
