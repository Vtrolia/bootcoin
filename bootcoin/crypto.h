#pragma once
#include <openssl/ssl.h>
#include <openssl/bio.h>

int generate_sha3_256_hash(char* input, size_t input_size, char result[65]);
