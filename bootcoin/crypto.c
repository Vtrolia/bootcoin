#include "crypto.h"


/**
* generates the Secure Hashing Algorithm 3 256 bit hash of the input string, and places the hash in a string passed in by the caller
* @param input: string to be hashed
* @param input_size: length of the input string
* @return: 0 upon success, -1 upon failure
*/
int generate_sha3_256_hash(char* input, size_t input_size, char result[HASH_LENGTH])
{
    if (!input || input_size == 0 || !result)
    {
        return -1;
    }

    // initialize OpenSSL and load the SHA3-256 algorithm to generate hash
    uint32_t digest_length = SHA256_DIGEST_LENGTH;
    EVP_MD* sha = EVP_sha3_256();
    uint8_t* digest = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();

    // if something can't be initialized, return error code
    if (!sha || !digest || !ctx)
    {
        return -2;
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
    return 0;
}


/**
* If this is a brand new wallet, a new private and public key will need to be generated, so this creates them. It will be used for
* signing transactions done by the current wallet as they will need to be signed to be considered valid. This creates the new keys and
* writes them out to private and public key files that can be read and accessed later for future use.
* @return: keypair upon successful creation of a private and public key, NULL upon SSL failures.
*/
RSA *initialize_private_and_public_keys()
{
    // generates the keypair
    RSA* keypair = RSA_new();
    BIGNUM* e = BN_new();
    BN_set_word(e, 17);
    if (!RSA_generate_key_ex(keypair, 2048, e, NULL))
    {
        return NULL;
    }
    // exponent no longer needed
    BN_free(e);

    // create the files for writing
    BIO *priv = BIO_new_file(PRIVKEY_FILE, "w");
    BIO* pub = BIO_new_file(PUBKEY_FILE, "w");
    if (!priv || !pub)
    {
        RSA_free(keypair);
        return NULL;
    }

    // write the private and public keys to files iot to be used later
    if (!PEM_write_bio_RSAPrivateKey(priv, keypair, NULL, NULL, 0, NULL, NULL) || !PEM_write_bio_RSAPublicKey(pub, keypair))
    {
        BIO_free(priv);
        BIO_free(pub);
        return NULL;
    }

    // return the newly created keypair for current usage
    BIO_free(priv);
    BIO_free(pub);
    return keypair;
}


/**
* If the keys have already been previously created, they will be stored in privkey.pem and pubkey.pem, and in order to
* be used they must be read from there files.
* @param keypair: an RSA keypair to be filled with the private and public key. 
* @return: 0 upon success, a negative integer is returned upon failure and keypair is set to NULL
*/
int load_public_and_private_keys(RSA* keypair)
{
    // fuck outta here
    if (!keypair)
    {
        return -1;
    }

    // load up the private/public keyfiles
    BIO *priv = BIO_new_file(PRIVKEY_FILE, "r");
    BIO* pub = BIO_new_file(PUBKEY_FILE, "r");
    if (!priv || !pub)
    {
        RSA_free(keypair);
        keypair = NULL;
        return -2;
    }
   
    // read them into the keypair variable
    if (!PEM_read_bio_RSAPrivateKey(priv, &keypair, NULL, NULL) || !PEM_read_bio_RSAPublicKey(pub, &keypair, NULL, NULL))
    {
        RSA_free(keypair);
        BIO_free(priv);
        BIO_free(pub);
        keypair = NULL;
        return -3;
    }

    // return success upon success
    BIO_free(priv);
    BIO_free(pub);
    return 0;
}

