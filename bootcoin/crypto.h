#pragma once
#include <openssl/ssl.h>
#include <openssl/bio.h>

#define HASH_LENGTH 65

int generate_sha3_256_hash(char* input, size_t input_size, char result[HASH_LENGTH]);
