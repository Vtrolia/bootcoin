#include "block.h"


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
* Takes in a block and converts it to a string, hashes it then places the hash into the input string. "Bootcoin" uses the new SHA3-256 algorithm for
* hashing its blocks. It will take longer than earlier editions of SHA, but it is more secure and less likely for a collision to happen
* @param cur_block: the block that is to be hashed and added to the blockchain
* @param result: the string where the resulting hash will be placed
* @return: 0 upon successful hashing of a block, a negative integer if anything goes wrong
*/
int block_hash(block* cur_block, char result[65])
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
    return 0;
}


