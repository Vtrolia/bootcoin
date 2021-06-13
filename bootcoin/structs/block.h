#ifndef BLOCK_H
#define BLOCK_H

#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include "transaction.h"
#include "../crypto.h"

/* basic building "block" of a blockchain to be added. */
typedef struct block
{
    uint64_t index;
    uint64_t stake_ind;
    char last_hash[HASH_LENGTH];
    transaction_node* tr_chain;
    time_t timestamp;
}
block;

/* chain of blocks, aka the actual block chain in a blockchain */
typedef struct block_node
{
    block data;
    struct block_node* next;
}
block_node;

/* functions */
int verify_proof(uint64_t last_proof, uint64_t proof_guess);
uint64_t proof_of_work(uint64_t last_proof);
int block_hash(block* cur_block, char result[HASH_LENGTH]);
#endif