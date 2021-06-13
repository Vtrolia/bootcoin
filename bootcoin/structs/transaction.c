#include "transaction.h"


/**
* Creates the most basic building block for a blockchain, a transaction. This is what a miner will verify and then
* create a hash of in order to verify and form into a block to then recieve bootcoins in exchange for its processing power
* @param sender: sender address
* @param recipient: recipient address
* @param amount: amount of bootcoins to exchange
* @return new_transaction: the new transaction, with a creation time and a hash, timestamp will be set to 0 in case of
* invalid parameters or 1 in case of a memory error
*/
transaction create_transaction(char* sender, char* recipient, uint64_t amount)
{
    // invalid params gotta go
    transaction new_transaction;
    if (!sender || !recipient || amount < 1)
    {
        new_transaction.timestamp = 0;
        return new_transaction;
    }

    // copy/paste all the basic transaction info
    new_transaction.amount = amount;
    new_transaction.sender = sender;
    new_transaction.recipient = recipient;

    // get the time the transaction was created
    new_transaction.timestamp = time(NULL);

    // check for memory errors when converting new_transaction into a string
    char* trs = transaction_string(&new_transaction);
    if (!trs)
    {
        new_transaction.timestamp = 1;
        return new_transaction;
    }

    // create the sha3 hash of the transaction
    char tr_hash[HASH_LENGTH] = { 0 };
    int hash_res = 0;
    if ((hash_res = generate_sha3_256_hash(trs, strlen(trs), tr_hash)) != 0)
    {
        if (hash_res == -1)
        {
            new_transaction.timestamp = 0;
        }

        else
        {
            new_transaction.timestamp = 1;
        }
        
        free(trs);
        return new_transaction;
    }

    // don't forget to free malloc'd memory
    free(trs);
    strncpy(new_transaction.hash, tr_hash, HASH_LENGTH);
    return new_transaction;
   
}


/**
* attaches a transaction to a transaction chain
* @param origin: the first transaction in a chain
* @param tr: new transaction to add to the block
* @return: 0 upon success, -1 upon failure
*/
int add_transaction_to_chain(transaction_node* origin, transaction_node* tr)
{
    // if an invalid pointer is passed in, return failure
    if (!origin || !tr)
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
    for (transaction_node* trav = origin; trav != NULL; trav = trav->next)
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
char* transaction_string(transaction* tr)
{
    // if no transaction, no string
    if (!tr)
    {
        return NULL;
    }

    // allocate a result string
    long unsigned res_size = (strlen(tr->sender) + strlen(tr->recipient) + sizeof(uint64_t));
    char* result = malloc(res_size);
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
* in order for a transaction to be ceritified, it will need to be signed by the sender
*/
int sign_transaction(RSA* keypair, RSA* sendkey, transaction* tr)
{
    // pissin me off with invalid params now
    if (!keypair || !sendkey || !tr)
    {
        return -1;
    }

    // compare hashes to ensure no tampering
    char new_hs[65] = { 0 };
    char* ts = transaction_string(tr);
    if (generate_sha3_256_hash(ts, strlen(ts), new_hs) < 0)
    {
        free(ts);
        return -2;
    }
    if (strncmp(tr->hash, new_hs, 64) != 0)
    {
        free(ts);
        return -3;
    }

    // make sure the keys aren't different
    if (memcmp(keypair, sendkey, sizeof(keypair)) != 0)
    {
        return -4;
    }

    // sign
    int siglen = 256;
    if (generate_rsa_signature(ts, strlen(ts), tr->signature, &siglen, sendkey) < 0)
    {
        free(ts);
        return -5;
    }

    free(ts);
    return 0;
}