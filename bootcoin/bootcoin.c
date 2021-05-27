//
//  bootcoin.c
//  Blockchain for the cryptocurrency codenamed "bootcoin" for now
//
//  Created by Vinny Trolia on 5/18/2021.
//  Copyright © 2021 Vincent Trolia. All rights reserved.
//
//  Basic blockchain functionality for the central server of "bootcoin" until a better name is given

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <openssl/ssl.h>
#include <openssl/bio.h>

// bootcoin errno
#define BOOTCOIN_NOERROR 0
#define BOOTCOIN_MEMORY_ERROR 1
#define BOOTCOIN_INVALID_PARAM_ERROR 2
#define BOOTCOIN_UNKNOWN_ERROR 255

static int bootcoin_errno = BOOTCOIN_NOERROR;

/* Basic information given for each bootcoin transaction for a block in the blockchain, a sender address, a recipient address, and the number of coins exchanged */
typedef struct transaction 
{
    char *sender;
    char *recipient;
    uint64_t amount;
}
transaction;

/* Used to store a "chain" of transactions on a block */
typedef struct transaction_node
{
    transaction tran;
    struct transaction_node *next;
}
transaction_node;

/* basic building "block" of a blockchain to be added. */
typedef struct block 
{
    uint64_t index;
    uint64_t stake_ind;
    char last_hash[65];
    transaction_node *tr_chain;
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

/* This is the actual structure of the "bootcoin" blockchain */
typedef struct Blockchain 
{
    block_node *chain;
    transaction_node *unconfirmed_transactions;
    uint64_t cur_index;
    char last_block_hash[65];
    block last_block;
}
Blockchain;


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



/**
* attaches a transaction to a transaction chain
* @param origin: the first transaction in a chain
* @param tr: new transaction to add to the block
* @return: 0 upon success, -1 upon failure
*/
int add_transaction_to_chain(transaction_node *origin, transaction_node *tr)
{
    // if an invalid pointer is passed in, return failure
    if(!origin || !tr)
    {
        bootcoin_errno = BOOTCOIN_INVALID_PARAM_ERROR;
        return -1;
    }

    // if theres only one transaction, don't need to try and traverse the whole chain
    bootcoin_errno = BOOTCOIN_NOERROR;
    if (!origin->next)
    {
        origin->next = tr;
        tr->next = NULL;
        return 0;
    }

    // if chain already exists, traverse to the end and attach the current transaction to the end
    for (transaction_node *trav = origin; trav != NULL; trav = trav->next)
    {
        if (trav->next == NULL)
        {
            trav->next = tr;
            tr->next = NULL;
            break;
        }
    }

    return 0;
}


/**
* As a placeholder, bootcoin is going to use a Proof-of-Work algorithm in order to process transactions. Because of this, a Bitcoin
* style Proof-of-Work will be used. For this, a proposed proof number and the last proof number will be hashed together and if the last
* four characters of the resulting hash are "0000", then it is considered valid.
* @param last_proof: Proof-of-Work number from the last block
* @param proof_guess: the current guess as to what this block's proof number will be
* @return: 0 upon success, a negative integer upon failure
*/
int verify_proof(uint64_t last_proof, uint64_t proof_guess)
{
    // put both proofs together in a string
    int guess_len = sizeof(uint64_t) * 2 + 1;
    char* guess = malloc(guess_len);
    if (!guess)
    {
        bootcoin_errno = BOOTCOIN_MEMORY_ERROR;
        return -1;
    }
    snprintf(guess, sizeof(uint64_t) * 2 + 1, "%llu%llu", last_proof, proof_guess);

    // generate the hash value of the two proofs
    char result[65] = { 0 };
    if (generate_sha3_256_hash(guess, guess_len, result) != 0)
    {
        free(guess);
        return -1;
    }

    // in order for a proof to be "correct", the hash must end with four trailing zeroes. if the hash does not end with this, it is
    // not the correct proof.
    free(guess);
    bootcoin_errno = BOOTCOIN_NOERROR;
    if (strncmp("0000", &result[guess_len - 4], 4) == 0)
    {
        return 0;
    }
    return -2;
}


/**
* Placeholder Proof-of-Work function to be used while Proof-of-Stake algorithm is under development. Guesses different proofs unti; the
* correct on is found
* @param last_proof: the proof number of the previous block
* @return new_proof: the proof number that creates the correct hash for this block
*/
uint64_t proof_of_work(uint64_t last_proof)
{
    uint64_t new_proof = 0;
    int status;

    // run until a correct proof is selected
    while ((status = verify_proof(last_proof, new_proof)) != 0)
    {
        // if there was an error, return zero. Bootcoin_errno is set accordingly so 0 is not mistaken as a correct proof
        if (status == -1)
        {
            return 0;
        }

        new_proof++;
    }

    return new_proof;
}


/**
* Converts a transaction into a hashable string
* @param tr: pointer to a transaction
* @return: a newly malloc'd string containing the details of the transaction passed in. NULL if there was an error
*/
char *transaction_string(transaction *tr)
{
    // if no transaction, no string
    if(!tr)
    {
        bootcoin_errno = BOOTCOIN_INVALID_PARAM_ERROR;
        return NULL;
    }
    
    // allocate a result string
    long unsigned res_size = (strlen(tr->sender) + strlen(tr->recipient) + sizeof(uint64_t));
    char *result = malloc(res_size);
    if (!result)
    {
        bootcoin_errno = BOOTCOIN_MEMORY_ERROR;
        return NULL;
    }

    // set the result string to empty then print the transaction details
    memset(result, 0, res_size);
    snprintf(result, res_size, "%s%s%llu", tr->sender, tr->recipient, tr->amount);
    bootcoin_errno = BOOTCOIN_NOERROR;
    return result;
}


/**
* Takes in a block and converts it to a string, hashes it then places the hash into the input string. "Bootcoin" uses the new SHA3-256 algorithm for
* hashing its blocks. It will take longer than earlier editions of SHA, but it is more secure and less likely for a collision to happen
* @param cur_block: the block that is to be hashed and added to the blockchain
* @param result: the string where the resulting hash will be placed
* @return: 0 upon successful hashing of a block, a negative integer if anything goes wrong
*/
int block_hash(block *cur_block, char result[65])
{
    // don't pass in empty paramters please
    if (!cur_block || !result)
    {
        bootcoin_errno = BOOTCOIN_INVALID_PARAM_ERROR;
        return -1;
    }

    char* block_str = NULL;
    size_t block_str_size = 0;

    // if the block passed in is the genesis block, there will be no transactions
    if (cur_block->index == 0)
    {
        // block will only contain basic metadata and an empty hash
        block_str_size = (sizeof(uint64_t) * 2) + 64 + sizeof(time_t) + strlen(cur_block->last_hash);
        block_str = malloc(block_str_size);
        if (!block_str)
        {
            bootcoin_errno = BOOTCOIN_MEMORY_ERROR;
            return -6;
        }
        memset(block_str, 0, block_str_size);
        snprintf(block_str, block_str_size, "%llu%llu%s%llu", cur_block->index, cur_block->stake_ind, cur_block->last_hash, cur_block->timestamp);
    }

    else
    {
        // only the genesis block should have an empty chain
        if (!cur_block->tr_chain)
        {
            bootcoin_errno = BOOTCOIN_INVALID_PARAM_ERROR;
            return -1;
        }
         
        // for some reason the first transaction needs to be sanitized so copy it into a freshly full 0 initialized string then pass it back to tran_string
        char* tran_string = transaction_string(&cur_block->tr_chain->tran);
        size_t initial_size = strlen(tran_string) + 1;
        char* sanitize = malloc(initial_size);
        if (!sanitize)
        {
            bootcoin_errno = BOOTCOIN_MEMORY_ERROR;
            return -2;
        }
        memset(sanitize, 0, initial_size);
        strcpy(sanitize, tran_string);
        free(tran_string);
        tran_string = sanitize;

        // each transaction in the block needs to be converted into a string to properly hash it
        for (transaction_node* first = cur_block->tr_chain->next; first != NULL; first = first->next)
        {
            size_t cur_size = strlen(tran_string) + 1;
            char* transtr_cpy = malloc(cur_size);
            if (!transtr_cpy)
            {
                bootcoin_errno = BOOTCOIN_MEMORY_ERROR;
                return -4;
            }

            // copy current tran_string into a temporary copy so that it can be resized
            memset(transtr_cpy, 0, cur_size);
            strncpy(transtr_cpy, tran_string, cur_size);
            char* next_str = transaction_string(&first->tran);
            if (!next_str)
            {
                free(transtr_cpy);
                break;
            }
            size_t new_size = strlen(transtr_cpy) + strlen(next_str);
            tran_string = malloc(new_size);
            if (!tran_string)
            {
                free(transtr_cpy);
                free(next_str);
                bootcoin_errno = BOOTCOIN_MEMORY_ERROR;
                return -6;
            }

            // Take the next transaction string then add it to the end of the current transaction_string. 
            memset(tran_string, 0, new_size);
            strncat(tran_string, transtr_cpy, strlen(transtr_cpy));
            strncat(tran_string, next_str, strlen(next_str));
            free(next_str);
            free(transtr_cpy);
        }

        // take all of the info from the block and paste it into a hashable string that contains all the data
        block_str_size = strlen(tran_string) + (sizeof(uint64_t) * 2) + 64 + sizeof(time_t) + strlen(cur_block->last_hash);
        block_str = malloc(block_str_size);
        if (!block_str)
        {
            free(tran_string);
            bootcoin_errno = BOOTCOIN_MEMORY_ERROR;
            return -6;
        }
        memset(block_str, 0, block_str_size);
        snprintf(block_str, block_str_size, "%llu%llu%s%s%llu", cur_block->index, cur_block->stake_ind, cur_block->last_hash, tran_string, cur_block->timestamp);
        free(tran_string);
    }

    // get the hash of the block, and return whether or not the operation was successful
    if (generate_sha3_256_hash(block_str, block_str_size, result) != 0)
    {
        free(block_str);
        return -7;
    }

    free(block_str);
    bootcoin_errno = BOOTCOIN_NOERROR;
    return 0;
}


/**
* Creates the initial block in the blockchain
*/
block genesis_block(void)
{
    // set all params to initializers for a Blockchain, with no transactions and the starting indexes for both chains.
    block genesis;
    genesis.index = 0;
    genesis.stake_ind = 0;
    strncat(genesis.last_hash, "0", 2);
    genesis.tr_chain = NULL;
    genesis.timestamp = time(NULL);
    return genesis;
}


/**
* takes a chain of transactions and creates a new block on the blockchain
* @param bc: active blockchain
* @param transactions: chain of verified transactions to go on a block
* @return new_block: the block just created, index will be -1 upon error
*/
block create_block(Blockchain* bc, transaction_node* transactions)
{
    // make sure the parameters exist and it's not creating the genesis block
    if (!bc || bc->cur_index < 1 || !transactions)
    {
        block new_block;
        new_block.index = 0;
        bootcoin_errno = BOOTCOIN_INVALID_PARAM_ERROR;
        return new_block;
    }
    
    // set the indexes and incriment then blockchain's global index of blocks
    block new_block;
    new_block.index = bc->cur_index;
    bc->cur_index++;
    new_block.stake_ind = 0;

    // add time and transactions
    strncpy(new_block.last_hash, bc->last_block_hash, 65);
    new_block.tr_chain = transactions;
    new_block.timestamp = time(NULL);
    bootcoin_errno = BOOTCOIN_NOERROR;
    return new_block;
}


/**
* Adds a new block to the block chain.
* @param bc: current blockchain
* @param new_block: the newest generated block to be added to the chain
* @return: 0 upon success, a negative integer upon failure
*/
int add_block_to_chain(Blockchain* bc, block_node* new_block)
{
    // no NULL params pls
    bootcoin_errno = BOOTCOIN_INVALID_PARAM_ERROR;
    if (!bc || !new_block)
    {
        return -1;
    }

    // genesis block should already exist in Blockchain
    if (!bc->chain)
    {
        return -2;
    }

    // traverse the block chain for the last entry and attach the new block to the end
    bootcoin_errno = BOOTCOIN_NOERROR;
    for (block_node* trav = bc->chain; trav != NULL; trav = trav->next)
    {
        if (trav->next == NULL)
        {
            trav->next = new_block;
            new_block->next = NULL;

            // set most recent block data to top of the blockchain
            bc->last_block = new_block->data;
            block_hash(&new_block->data, bc->last_block_hash);
        }
        break;
    }

    return 0;
}


/**
* Double checks the work done by the miner in the current block is valid. 
* @param last_block: the most recently added block in the blockchain
* @param proposed_block: the block that is trying to be added to the blockchaijn
* @returns: 1 upon a valid block, 0 upon unvalid block. A negative int is returned for errors and bootcoin_errno is set accordingly
*/
int check_block_validity(block *last_block, block *proposed_block)
{
    // invalid param check
    if (!last_block || !proposed_block)
    {
        bootcoin_errno = BOOTCOIN_INVALID_PARAM_ERROR;
        return - 1;
    }

    // check to see if the new block has the correc index
    if (proposed_block->index != (last_block->index + 1))
    {
        return 0;
    }

    // checking for block hash errors
    char last_hash[65] = { 0 };
    if (block_hash(last_block, last_hash) < 0)
    {
        return -2;
    }

    // make sure the hash of the previous block is the value the new block has for last_hash
    if (strncmp(last_hash, proposed_block->last_hash, 64) != 0)
    {
        printf("failed hash\n");
        return 0;
    }

    // ensure that the Proof-of-Work was accurately completed by the miner
    if (verify_proof(last_block->stake_ind, proposed_block->stake_ind) != 0)
    {
        if (bootcoin_errno != BOOTCOIN_NOERROR)
        {
            return -3;
        }
        printf("failed proof\n");
        return 0;
    }

    // if this block was made before the last one, invalid
    if (last_block->timestamp >= proposed_block->timestamp)
    {
        printf("failed timestamp %llu beats %llu\n", last_block->timestamp, proposed_block->timestamp);
        return 0;
    }

    // 1, aka true, is success
    return 1;
}


/**
* Intitializes a Blockchain struct with all the basic genisys block info to create it. Also creates the genesis block and adds it to the chain.
* If there is a failure in creating the blockchain, it will set the current index to -1 before it returns.
*/
Blockchain initialize_blockchain(void)
{
    // genesis block information
    Blockchain block_chain;
    block_chain.cur_index = 0;
    strncpy(block_chain.last_block_hash, "0", 2);

    // malloc the first block node so that the scope won't destroy the chain
    block_node *bn = malloc(sizeof(block_node));
    if (!bn)
    {
        block_chain.cur_index = -1;
        return block_chain;
    }

    // create the genesis block and add it
    bn->data = genesis_block();
    bn->next = NULL;
    block_chain.chain = bn;
    block_hash(&bn->data, block_chain.last_block_hash);

    // update index and last block so it can easily be popped later
    block_chain.cur_index = 1;
    block_chain.last_block = bn->data;
    return block_chain;


}


/**
* This is where the money is made in Proof-of-Work based cryptocurrencies. The miner will compute the proof of work and then create a 
* block. This will be sent to be proofread then added to the blockchain.
* @param bc: current blockchain
* @return mined_block: the block mined by the miner
*/
block mine_block(Blockchain* bc)
{
    // complete the proof-of-work
    uint64_t new_proof = proof_of_work(bc->last_block.stake_ind);
    block mined_block;
    if (bootcoin_errno != BOOTCOIN_NOERROR)
    {
        mined_block.index = 0;
        return mined_block;
    }

    // then create the block
    mined_block = create_block(bc, bc->unconfirmed_transactions);
    if (mined_block.index == 0)
    {
        return mined_block;
    }

    mined_block.stake_ind = new_proof;
    return mined_block;
}


int main()
{
    Blockchain battalion_commander = initialize_blockchain();
    transaction t1;
    t1.amount = 30;
    t1.sender = "1GUA9UZMifAsoKphEJbzrRCP4qTLpa7yub";
    t1.recipient = "1GUA9UZMifAsoKphEJbzrRCP4qTLpa7yub";

    transaction t2;
    t2.amount = 1;
    t2.sender = "DQXFFxXbhK8Es9DCJX2NnXRj2sxbfLpKYH";
    t2.recipient = "DQXFFxXbhK8Es9DCJX2NnXRj2sxbfLpKYH";

    transaction t3;
    t3.amount = 50000;
    t3.sender = "ak_2hrCzNBYhFe4qPDF7inqnKjykJtYZVX1zQGpV4N9nqUzZu6E4t";
    t3.recipient = "ak_2hrCzNBYhFe4qPDF7inqnKjykJtYZVX1zQGpV4N9nqUzZu6E4t";

    struct transaction_node n1;
    n1.tran = t1;
    n1.next = NULL;
    struct transaction_node n2;
    n2.tran = t2;
    n2.next = NULL;
    struct transaction_node n3;
    n3.tran = t3;
    n3.next = NULL;
    
    add_transaction_to_chain(&n1, &n2);
    add_transaction_to_chain(&n1, &n3);
    battalion_commander.unconfirmed_transactions = &n1;
    block test_block = mine_block(&battalion_commander);
    if (test_block.index == 0)
    {
        return -1;
    }

    test_block.timestamp += 100;
    if (check_block_validity(&battalion_commander.last_block, &test_block))
    {
        if (add_block_to_chain(&battalion_commander, &test_block) != 0)
        {
            printf("Failed to add block\n");
            return -2;
        }
        char hash_of_test[65] = { 0 };
        block_hash(&test_block, hash_of_test);
        printf("Successfully added block %s, aka %s at index %llu at %llu\n", hash_of_test, battalion_commander.last_block_hash, test_block.index, test_block.timestamp);
        return 0;
    }

    printf("Block was not valid\n");
    return -3;
    
}