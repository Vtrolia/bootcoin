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
    BIO *priv = BIO_new_file(PRIVKEY_FILE, "wb");
    BIO* pub = BIO_new_file(PUBKEY_FILE, "wb");
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
* @return: keypair filled with a private and public key. Upon failure, keypair is set to NULL
*/
RSA *load_public_and_private_keys()
{
    // fuck outta here
    RSA* keypair = RSA_new();
    if (!keypair)
    {
        return NULL;
    }

    // load up the private/public keyfiles
    BIO *priv = BIO_new_file(PRIVKEY_FILE, "rb");
    BIO* pub = BIO_new_file(PUBKEY_FILE, "rb");
    if (!priv || !pub)
    {
        RSA_free(keypair);
        return NULL;
    }
   
    // read them into the keypair variable
    if (!PEM_read_bio_RSAPrivateKey(priv, &keypair, NULL, NULL) || !PEM_read_bio_RSAPublicKey(pub, &keypair, NULL, NULL))
    {
        RSA_free(keypair);
        BIO_free(priv);
        BIO_free(pub);
        return NULL;
    }

    // return success upon success
    BIO_free(priv);
    BIO_free(pub);
    return keypair;
}



/**
* In order to verify transactions as being legitimate, they will need to be signed by the sender's private key. For this,
* a string will be input and the signature returned, utilizing sha3_256.
* @param msg: string to be signed
* @param msg_len: length of msg
* @param sig: the string that will hold the signature
* @param sig_len: length of memory allocated to sig, will be set to length of data in sig upon successful signing
* @param keypair: the active private and public key
* @return: 0 upon success, negative integer upon failure.
*/
int generate_rsa_signature(char *msg, int msg_len, char *sig, int *sig_len, RSA* keypair)
{
    // miss me with that null shit
    if (!msg || !sig || !keypair)
    {
        return -1;
    }
    
    // set the private key
    EVP_MD_CTX* md_ctx = EVP_MD_CTX_new();
    EVP_PKEY* priv_k = EVP_PKEY_new();
    EVP_PKEY_assign_RSA(priv_k, keypair);
    if (!md_ctx || !priv_k)
    {
        return -2;
    }

    // sign and spit out the digest
    if (EVP_DigestSignInit(md_ctx, NULL, EVP_sha3_256(), NULL, priv_k) < 1)
    {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(priv_k);
        return -3;
    }
    if (EVP_DigestSignUpdate(md_ctx, msg, msg_len) < 1)
    {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(priv_k);
        return -4;
    }
    if (EVP_DigestSignFinal(md_ctx, sig, sig_len) < 1)
    {
        EVP_MD_CTX_free(md_ctx);
        EVP_PKEY_free(priv_k);
        return -7;
    }

    // free up our, shall we say, nagging considerations?
    EVP_MD_CTX_free(md_ctx);
    EVP_PKEY_free(priv_k);
    return 0;
}