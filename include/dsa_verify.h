// TODO: Insert license text

#ifndef _DSA_VERIFY_H_
#define _DSA_VERIFY_H_

#include <stdint.h>
#include <stddef.h>

/** @brief Size of a SHA1 hash, in bytes */
#define SHA1_HASH_SIZE 20

enum
{
	DSA_VERIFICATION_OK     =  1, ///< Verification successful
	DSA_VERIFICATION_FAILED =  0, ///< Verification failed
	DSA_GENERIC_ERROR       = -1, ///< Generic error, verification was not performed
	DSA_KEY_FORMAT_ERROR    = -2, ///< Invalid public key format
	DSA_KEY_PARAM_ERROR     = -3, ///< Invalid/missing public key parameters
	DSA_SIGN_FORMAT_ERROR   = -4, ///< Invalid signature format
	DSA_SIGN_PARAM_ERROR    = -5  ///< Invalid/missing signature parameters
};

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Verify a given blob
 *
 * This function verifies a blob of data using the given public key and signature.
 * Effectively hashes the blob using SHA1 and afterwards calls @ref dsa_verify_hash
 * in order to verify data validity.
 *
 * @param data      Pointer to the beginning of the data blob
 * @param data_len  Length of the data blob
 * @param pubkey    Null-terminated string with the contents of the public key,
 *                  in PEM format.
 * @param sig       Null-terminated string with the signature of the file,
 *                  encoded in base64.
 *
 * @returns 1 (@ref DSA_VERIFICATION_OK) on success, 0 (@ref DSA_VERIFICATION_FAILED)
 * on verification failure or any of @ref DSA_GENERIC_ERROR, @ref DSA_KEY_FORMAT_ERROR,
 * @ref DSA_KEY_PARAM_ERROR, @ref DSA_SIGN_FORMAT_ERROR or @ref DSA_SIGN_PARAM_ERROR
 * on error.
 */
int dsa_verify_blob(const char* data, size_t data_len, const char* pubkey, const char* sig);

/**
 * Verify a given SHA1 hash
 *
 * This function verifies a SHA1 hash using the given public key and signature.
 *
 * @param sha1      SHA1 hash to be verified
 * @param data_len  Length of the data blob
 * @param pubkey    Null-terminated string with the contents of the public key,
 *                  in PEM format.
 * @param sig       Null-terminated string with the signature of the file,
 *                  encoded in base64.
 *
 * @returns 1 (@ref DSA_VERIFICATION_OK) on success, 0 (@ref DSA_VERIFICATION_FAILED)
 * on verification failure or any of @ref DSA_GENERIC_ERROR, @ref DSA_KEY_FORMAT_ERROR,
 * @ref DSA_KEY_PARAM_ERROR, @ref DSA_SIGN_FORMAT_ERROR or @ref DSA_SIGN_PARAM_ERROR
 * on error.
 */
int dsa_verify_hash(const uint8_t sha1[SHA1_HASH_SIZE], const char* pubkey, const char* sig);

/**
 * Verify a given SHA1 hash, key & signature in DER form
 *
 * This function verifies a SHA1 hash using the given public key and signature.
 *
 * @param sha1      SHA1 hash to be verified
 * @param pubkey      Binary DER representation of the public key
 * @param pubkey_len  Lenght of the public key
 * @param sig         Binary DER representation of the signature of the file
 * @param sig_len     Length of the signature
 *
 * @returns 1 (@ref DSA_VERIFICATION_OK) on success, 0 (@ref DSA_VERIFICATION_FAILED)
 * on verification failure or any of @ref DSA_GENERIC_ERROR, @ref DSA_KEY_FORMAT_ERROR,
 * @ref DSA_KEY_PARAM_ERROR, @ref DSA_SIGN_FORMAT_ERROR or @ref DSA_SIGN_PARAM_ERROR
 * on error.
 */
int dsa_verify_hash_der(const uint8_t sha1[SHA1_HASH_SIZE], const unsigned char* pubkey, size_t pubkey_len, const unsigned char* sig, size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif
