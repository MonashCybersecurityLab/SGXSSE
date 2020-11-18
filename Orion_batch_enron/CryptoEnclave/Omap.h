#ifndef OMAP_H
#define OMAP_H

#include "AVLTree.h"
using namespace std;

class OMAP {
private:
    Bid rootKey;
    unsigned int rootPos;
    AVLTree* treeHandler;

public:
    OMAP(const unsigned char *key, int _numBucketLeaf, int data_structure);
    ~OMAP();
    void insert(Bid key, unsigned int value);
    unsigned int find(Bid key);

    void batchInsert(map<Bid, unsigned int> pairs);
    vector<unsigned int> batchSearch(vector<Bid> keys);

};


#endif /* OMAP_H */
