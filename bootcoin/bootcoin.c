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

#include "structs/block.h"
#include "crypto.h"

// bootcoin errno
#define BOOTCOIN_NOERROR 0
#define BOOTCOIN_MEMORY_ERROR 1
#define BOOTCOIN_INVALID_PARAM_ERROR 2
#define BOOTCOIN_UNKNOWN_ERROR 255

static int bootcoin_errno = BOOTCOIN_NOERROR;


/* This is the actual structure of the "bootcoin" blockchain */
typedef struct Blockchain 
{
    block_node *chain;
    transaction_node *unconfirmed_transactions;
    uint64_t cur_index;
    char last_block_hash[HASH_LENGTH];
    block last_block;
}
Blockchain;


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
        return new_block;
    }
    
    // set the indexes and incriment then blockchain's global index of blocks
    block new_block;
    new_block.index = bc->cur_index;
    bc->cur_index++;
    new_block.stake_ind = 0;

    // add time and transactions
    strncpy(new_block.last_hash, bc->last_block_hash, HASH_LENGTH);
    new_block.tr_chain = transactions;
    new_block.timestamp = time(NULL);
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
    char last_hash[HASH_LENGTH] = { 0 };
    int errval = 0;
    if ((errval = block_hash(last_block, last_hash)) < 0)
    {
        if (errval == -1)
        {
            bootcoin_errno = BOOTCOIN_INVALID_PARAM_ERROR;
        }

        else if (errval == -2)
        {
            bootcoin_errno = BOOTCOIN_MEMORY_ERROR;
        }
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
    /*Blockchain battalion_commander = initialize_blockchain();
    transaction t1 = create_transaction("1GUA9UZMifAsoKphEJbzrRCP4qTLpa7yub", "1GUA9UZMifAsoKphEJbzrRCP4qTLpa7yub", 30);
    if (t1.timestamp == 0)
    {
        printf("invalid param error\n");
        return -1;
    }

    else if (t1.timestamp == 1)
    {
        printf("memoryv error\n");
        return -2;
    }

    printf("Transaction created at %llu with a hash value of: %s\n\n", t1.timestamp, t1.hash);

    transaction t2 = create_transaction("DQXFFxXbhK8Es9DCJX2NnXRj2sxbfLpKYH", "DQXFFxXbhK8Es9DCJX2NnXRj2sxbfLpKYH", 1);
    if (t2.timestamp == 0)
    {
        printf("invalid param error\n");
        return -1;
    }

    else if (t2.timestamp == 1)
    {
        printf("memoryv error\n");
        return -2;
    }

    printf("Transaction created at %llu with a hash value of: %s\n\n", t2.timestamp, t2.hash);
    transaction t3 = create_transaction("ak_2hrCzNBYhFe4qPDF7inqnKjykJtYZVX1zQGpV4N9nqUzZu6E4t", "ak_2hrCzNBYhFe4qPDF7inqnKjykJtYZVX1zQGpV4N9nqUzZu6E4t", 50000);
    if (t3.timestamp == 0)
    {
        printf("invalid param error\n");
        return -1;
    }

    else if (t3.timestamp == 1)
    {
        printf("memoryv error\n");
        return -2;
    }
    printf("Transaction created at %llu with a hash value of: %s\n\n", t3.timestamp, t3.hash);
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
        block_node bn;
        bn.data = test_block;
        bn.next = NULL;
        if (add_block_to_chain(&battalion_commander, &bn) != 0)
        {
            printf("Failed to add block\n");
            return -2;
        }
        char hash_of_test[HASH_LENGTH] = { 0 };
        block_hash(&test_block, hash_of_test);
        printf("Successfully added block %s, aka %s at index %llu at %llu\n", hash_of_test, battalion_commander.last_block_hash, test_block.index, test_block.timestamp);
        return 0;
    }

    printf("Block was not valid\n");
    return -3;*/

    RSA* keys = initialize_private_and_public_keys();
    RSA* keys2 = load_public_and_private_keys();

    char* signature = malloc(257);
    int siglen = 256;;
    transaction t1 = create_transaction("1GUA9UZMifAsoKphEJbzrRCP4qTLpa7yub", "1GUA9UZMifAsoKphEJbzrRCP4qTLpa7yub", 30);
    printf("%i\n%s\n", sign_transaction(keys, keys2, &t1), t1.signature);

}