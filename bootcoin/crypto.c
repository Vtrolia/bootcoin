#include "crypto.h"
#include "err/bootcoin_errno.h"

bootcoin_errno = BOOTCOIN_NOERROR;

/**
* generates the Secure Hashing Algorithm 3 256 bit hash of the input string, and places the hash in a string passed in by the caller
* @param input: string to be hashed
* @param input_size: length of the input string
* @return: 0 upon success, -1 upon failure
*/
int generate_sha3_256_hash(char* input, size_t input_size, char result[65])
{
    // initialize OpenSSL and load the SHA3-256 algorithm to generate hash
    uint32_t digest_length = SHA256_DIGEST_LENGTH;
    EVP_MD* sha = EVP_sha3_256();
    uint8_t* digest = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // if something can't be initialized, return error code
    if (!sha || !digest || !ctx)
    {
        bootcoin_errno = BOOTCOIN_MEMORY_ERROR;
        return -1;
    }

    // hash the block string
    EVP_DigestInit_ex(ctx, sha, NULL);
    EVP_DigestUpdate(ctx, input, input_size);
    EVP_DigestFinal_ex(ctx, digest, &digest_length);

    // print out the hash digest in a readable format into the result string
    for (unsigned int i = 0; i < digest_length; i++)
    {
        sprintf(result + (i * 2), "%02x", digest[i]);
    }

    // free then return success
    EVP_MD_CTX_destroy(ctx);
    OPENSSL_free(digest);
    bootcoin_errno = BOOTCOIN_NOERROR;
    return 0;
}