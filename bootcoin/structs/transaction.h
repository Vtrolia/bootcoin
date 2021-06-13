#ifndef TRANSACTION_H
#define TRANSACTION_H

#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../crypto.h"

/* Basic information given for each bootcoin transaction for a block in the blockchain, a sender address, a recipient address, and the number of coins exchanged */
typedef struct transaction
{
    uint64_t amount;
    time_t timestamp;
    char* sender;
    char* recipient;
    char hash[HASH_LENGTH];
    char signature[256];
}
transaction;

/* Used to store a "chain" of transactions on a block */
typedef struct transaction_node
{
    transaction tran;
    struct transaction_node* next;
}
transaction_node;

/* functions */
int add_transaction_to_chain(transaction_node* origin, transaction_node* tr);
char* transaction_string(transaction* tr);
transaction create_transaction(char* sender, char* recipient, uint64_t amount);
int sign_transaction(RSA* keypair, RSA* sendkey, transaction* tr);
#endif