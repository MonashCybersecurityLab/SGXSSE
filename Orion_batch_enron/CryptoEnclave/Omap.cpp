#include "Omap.h"
#include <stdio.h>

#include "CryptoEnclave_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "Oram.h"
#include "../common/data_type.h"
#include "../common/data_type2.h"
#include "EnclaveUtils.h"


OMAP::OMAP(const unsigned char *key, int _numBucketLeaf,int data_structure) {
    treeHandler = new AVLTree(key, _numBucketLeaf, data_structure);
}

OMAP::~OMAP() {
    free(treeHandler);
}


unsigned int OMAP::find(Bid key) {
    Bid empty_key;

    if (rootKey == empty_key) {
        return 0;
    }

    treeHandler->startOperation(false);
    Node* node = new Node();
    node->key = rootKey;
    node->pos = rootPos;
    auto resNode = treeHandler->search(node, key);
    unsigned int res = 0;
    if (resNode != NULL) {
       res = resNode->value;
    }
    treeHandler->finishOperation(true, rootKey, rootPos);
    return res;
}

void OMAP::insert(Bid key, unsigned int value) {
    

    treeHandler->startOperation(false);
    Bid empty_key;
    if (rootKey == empty_key) {
        //printf("OMAP::insert insert empty Key");
        rootKey = treeHandler->insert(empty_key, rootPos, key, value);
    } else {
        //printf("OMAP::insert not insert empty Key");
        rootKey = treeHandler->insert(rootKey, rootPos, key, value);
    }
    treeHandler->finishOperation(false, rootKey, rootPos);
    //printf("OMAP::insert finish finalisation");
}

void OMAP::batchInsert(map<Bid, unsigned int> pairs) {
    

    
    treeHandler->startOperation(true);
    Bid empty_key;

    int count = 0;

    for (auto pair : pairs) {

        if (rootKey == empty_key) {
            rootKey = treeHandler->insert(empty_key, rootPos, pair.first, pair.second);
        } else {
            rootKey = treeHandler->insert(rootKey, rootPos, pair.first, pair.second);
        }

        count++;

        if(count%100000==0 || count == pairs.size()){ 
             printf("Processing search batch %d",count);
             treeHandler->finishOperation(false,rootKey, rootPos);
             treeHandler->startOperation(true);
         }
    }
    //treeHandler->finishOperation(false,rootKey, rootPos);
}

vector<unsigned int> OMAP::batchSearch(vector<Bid> keys) {
    
    vector<unsigned int> result;

    treeHandler->startOperation(false);
    
    Node* node = new Node();
    node->key = rootKey;
    node->pos = rootPos;

    vector<Node*> resNodes;
    treeHandler->batchSearch(node, keys, &resNodes);
    for (Node* n : resNodes) {
        unsigned int res;
        if (n != NULL) {
            result.push_back(n->value);
        } else {
            result.push_back(0);
        }
    }
    treeHandler->finishOperation(true, rootKey, rootPos);
    return result;
}

