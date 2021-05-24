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
        return -1;
    }

    // if theres only one transaction, don't need to try and traverse the whole chain
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
* Converts a transaction into a hashable string
* @param tr: pointer to a transaction
* @return: a newly malloc'd string containing the details of the transaction passed in. NULL if there was an error
*/
char *transaction_string(transaction *tr)
{
    // if no transaction, no string
    if(!tr)
    {
        return NULL;
    }
    
    // allocate a result string
    long unsigned res_size = (strlen(tr->sender) + strlen(tr->recipient) + sizeof(uint64_t));
    char *result = malloc(res_size);
    if (!result)
    {
        return NULL;
    }

    // set the result string to empty then print the transaction details
    memset(result, 0, res_size);
    snprintf(result, res_size, "%s%s%llu", tr->sender, tr->recipient, tr->amount);
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
            return -1;
        }
         
        // for some reason the first transaction needs to be sanitized so copy it into a freshly full 0 initialized string then pass it back to tran_string
        char* tran_string = transaction_string(&cur_block->tr_chain->tran);
        size_t initial_size = strlen(tran_string) + 1;
        char* sanitize = malloc(initial_size);
        if (!sanitize)
        {
            return -2;
        }
        memset(sanitize, 0, initial_size);
        strcpy(sanitize, tran_string);
        free(tran_string);
        tran_string = sanitize;

        // failure? piss.
        if (!tran_string)
        {
            return -3;
        }

        // each transaction in the block needs to be converted into a string to properly hash it
        for (transaction_node* first = cur_block->tr_chain->next; first != NULL; first = first->next)
        {
            size_t cur_size = strlen(tran_string) + 1;
            char* transtr_cpy = malloc(cur_size);
            if (!transtr_cpy)
            {
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
                return -5;
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
            return -6;
        }
        memset(block_str, 0, block_str_size);
        snprintf(block_str, block_str_size, "%llu%llu%s%s%llu", cur_block->index, cur_block->stake_ind, cur_block->last_hash, tran_string, cur_block->timestamp);
        free(tran_string);
    }

    // initialize OpenSSL and load the SHA3-256 algorithm to generate hash
    uint32_t digest_length = SHA256_DIGEST_LENGTH;
    EVP_MD *sha = EVP_sha3_256();
    uint8_t *digest = OPENSSL_malloc(SHA256_DIGEST_LENGTH);
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();

    if(!sha || !digest || !ctx)
    {
        free(block_str);
        return -7;
    }

    // hash the block string
    EVP_DigestInit_ex(ctx, sha, NULL);
    EVP_DigestUpdate(ctx, block_str, block_str_size);
    EVP_DigestFinal_ex(ctx, digest, &digest_length);

    // print out the hash digest in a readable format into the result string
    for(unsigned int i = 0; i < digest_length; i++)
    {
        sprintf(result + (i * 2), "%02x", digest[i]);
    }

    // free then return success
    EVP_MD_CTX_destroy(ctx);
    OPENSSL_free(digest);
    free(block_str);
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
* @param stake_index: current proof of work, will be shifted to a proof of stake soon
* @param transactions: chain of verified transactions to go on a block
* @return new_block: the block just created, index will be -1 upon error
*/
block create_block(Blockchain* bc, uint64_t stake_index, transaction_node* transactions)
{
    // make sure the parameters exist and it's not creating the genesis block
    if (!bc || bc->cur_index < 1 || !transactions)
    {
        block new_block;
        new_block.index = -1;
        return new_block;
    }
    
    // set the indexes and incriment then blockchain's global index of blocks
    block new_block;
    new_block.index = bc->cur_index;
    bc->cur_index++;
    new_block.stake_ind = stake_index;

    // add time and transactions
    strncpy(new_block.last_hash, bc->last_block_hash, 65);
    new_block.tr_chain = transactions;
    new_block.timestamp = time(NULL);

    return new_block;
}


int main()
{
    Blockchain battalion_commander;
    battalion_commander.chain = NULL;
    battalion_commander.cur_index = 2;
    strncpy(battalion_commander.last_block_hash, "0", 2);
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
    block gen_block = genesis_block();
    
    add_transaction_to_chain(&n1, &n2);
    add_transaction_to_chain(&n1, &n3);
    block test_block = create_block(&battalion_commander, 1, &n1);
    

    char res[65];
    for (int i = 0; i < 5; i++)
    {
        block_hash(&test_block, res);
        printf("%s\n", res);
    }
}