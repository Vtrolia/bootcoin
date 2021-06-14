#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/ssl.h>
#include <openssl/bio.h>

// so the names aren't repeated a million times
#define HASH_LENGTH 65
#define PRIVKEY_FILE "privkey.pem"
#define PUBKEY_FILE "pubkey.pem"

/* functions */
int generate_sha3_256_hash(char* input, size_t input_size, char result[HASH_LENGTH]);
RSA *initialize_private_and_public_keys(void);
RSA *load_public_and_private_keys();
int generate_rsa_signature(char* msg, int msg_len, char* sig, int* sig_len, RSA* keypair);

#endif
