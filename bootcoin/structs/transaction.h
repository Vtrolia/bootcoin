#pragma once

#include <stdint.h>
#include <time.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include "../err/bootcoin_errno.h"

/* Basic information given for each bootcoin transaction for a block in the blockchain, a sender address, a recipient address, and the number of coins exchanged */
typedef struct transaction
{
    char* sender;
    char* recipient;
    uint64_t amount;
    time_t timestamp;
    char hash[64];
}
transaction;

/* Used to store a "chain" of transactions on a block */
typedef struct transaction_node
{
    transaction tran;
    struct transaction_node* next;
}
transaction_node;

int add_transaction_to_chain(transaction_node* origin, transaction_node* tr);
char* transaction_string(transaction* tr);
