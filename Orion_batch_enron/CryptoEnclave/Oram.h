#ifndef ORAM_H
#define ORAM_H


#include "../common/data_type.h"
#include "../common/data_type2.h"
#include <random>
#include <vector>
#include <set>
#include <cstring>
#include <map>
#include "Bid.h"


using namespace std;

class Node
{
public:
    Node(){

    }
    
    ~Node(){

    }

    Bid key;
    unsigned int value;
    unsigned int pos;
    unsigned int height;

    Bid leftID;
    unsigned int leftPos;

    Bid rightID;
    unsigned int rightPos;
};

class Oram
{

private:
    
    int visitedOcallsWrite;
    int visitedOcallsRead;
    
    size_t depth;
    size_t blockSize; //AVL Node size
    size_t bucketSize;// a bucket size = blockSize * Z
    size_t enc_bucketSize; // this is bucketSize + AESGCM_MAC_SIZE + AESGCM_IV_SIZE 
    int bucketCount;
    int numBucketLeaf;

    bool batchWrite=false;
    bool isWriteOnly=false;

    //set<Bid> detRead; //fetched nodes during deterministic read isWriteOnly=true
    std::map<Bid, Node*> cache;

    //these leafList tracks the leafPos used during ORAM write operation and be reset after finaliseOperation()
    vector<unsigned int> leafList;
    vector<int> readviewmap; //important map to track the bucketIndex has been read from outside, avoiding overwriting current nodes in cache
    vector<int> writeviewmap; //important map to track the bucketIndex in finaliseOp to avoid overwriting new nodes to outside
    set<Bid> modified; //stored the AVL node key has been written and will be  assigned new ranPos in finaliseOperation()

    int readCnt=0; //keep track number of leafRead for both cache hit/miss to do padding in finaliseOperation

    void to_bytes1(const Node& object, unsigned char* des);
    void from_bytes1(const unsigned char* res, Node& object);



    
    int GetNodeOnPath(unsigned int leaf, int depth);//
    std::vector<Bid> GetIntersectingBlocks(int leaf, int depth);//

    void FetchPath(unsigned int leaf);//
    void WritePath(unsigned int leaf, int level);//

    Node* ReadData(Bid id);//
    void WriteData(Bid, Node* b);//


    void Access(Bid bid, Node*& node, unsigned int lastLeaf, unsigned int newLeaf);//
    void Access(Bid, Node*& node);//

    void deserialiseBucket(const unsigned char* bucket_str_tmp, Node* tempNodes[Z]);//

    Bid empty_key;

    unsigned char KC[ENC_KEY_SIZE];

    int data_structure;
    
public:

    Oram(const unsigned char *treeKey, int _numBucketLeaf, int data_structure);//

    unsigned int RandomPath();//
    Node* ReadNode(Bid bid, int lastLeaf, int newLeaf);//
    Node* ReadNode(Bid id);//
    int WriteNode(Bid bid, Node* n);//
    void start(bool batchWrite);//
    void finalise(bool find, Bid& rootKey, unsigned int& rootPos);  //  

};
#endif