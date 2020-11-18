#ifndef AVLTREE_H
#define AVLTREE_H

#include "Oram.h"
#include "EnclaveUtils.h"
#include "string.h"


class AVLTree
{

private:
    Bid empty_key;
    Oram *oram;
    int height(Bid N, unsigned int& leaf);//
    int max(int a, int b);//
    Node* newNode(Bid key, unsigned int value);//
    Node* rightRotate(Node* y);//
    Node* leftRotate(Node* x);//
    int getBalance(Node* N);//


public:
    AVLTree(const unsigned char *key, int _numBucketLeaf, int data_structure);//
    
    ~AVLTree();//

    Bid insert(Bid rootKey, unsigned int& pos, Bid key, unsigned int value);//
    Node* search(Node* head, Bid key);//
    void batchSearch(Node* head, vector<Bid> keys, vector<Node*>* results);
    void startOperation(bool batchWrite = false);
    void finishOperation(bool find, Bid& rootKey, unsigned int& rootPos);

};

#endif