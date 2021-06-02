#include "transaction.h"


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

