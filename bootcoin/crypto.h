#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/ssl.h>
#include <openssl/bio.h>

#define HASH_LENGTH 65
#define PRIVKEY_FILE "privkey.pem"
#define PUBKEY_FILE "pubkey.pem"

int generate_sha3_256_hash(char* input, size_t input_size, char result[HASH_LENGTH]);
RSA *initialize_private_and_public_keys(void);
int load_public_and_private_keys(RSA* keypair);
#endif
