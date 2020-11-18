#include <cstdlib>
#include <stdio.h>

#include "CryptoEnclave_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "Oram.h"
#include "../common/data_type.h"
#include "../common/data_type2.h"
#include "EnclaveUtils.h"

Oram::Oram(const unsigned char *treeKey, int _numBucketLeaf, int _data_structure)
{
    //store the enc/dec key
    memcpy(KC, treeKey, ENC_KEY_SIZE);

    numBucketLeaf = _numBucketLeaf;
   
    depth = floor(log2(_numBucketLeaf)); // e.g. _numBucketLeaf =8 -> depth = 3
    bucketCount = pow(2, depth + 1) - 1; // depth = 3 -> bucketCount = 15
    

    data_structure = _data_structure;
    //1: omap search
    //2: omap update

    printf("Total bucket count %d", bucketCount);
    printf("Tree height %d", depth);
    printf("Total numBucketLeaf %d\n", numBucketLeaf);

    //capture the block AVL node size and a bucketSize, enc_bucket_size
    blockSize = sizeof(Node);
    bucketSize = blockSize * Z;
    enc_bucketSize =  AESGCM_MAC_SIZE + AESGCM_IV_SIZE + bucketSize;

    //store empty buckets to RAMStore via #bucketCOunt ocalls
    for (size_t i = 0 ; i < bucketCount; i++){ //Z* bucketCount
        unsigned char* bucket_src =  (unsigned char *) malloc( bucketSize * sizeof(unsigned char));

        //init AVL nodes in this bucket index i 
        for (int j=0; j < Z; j++){
            Node node;
            node.key = empty_key;

            node.leftID = empty_key;
            node.rightID = empty_key;

            unsigned char* node_src = (unsigned char *) malloc( blockSize * sizeof(unsigned char));
            to_bytes1(node,node_src);

            //memcpy the node_src to the bucket_src
            memcpy(bucket_src + (j*blockSize), node_src, blockSize);
            
            free(node_src);
        }

        //encrypt the bucket here before calling the ocall, maybe with the new len? 
        unsigned char* enc_bucket_src = (unsigned char*) malloc(enc_bucketSize);
        enc_aes_gcm(KC,bucket_src,bucketSize,enc_bucket_src,enc_bucketSize);

        //should be bucket batch later for time saving
        ocall_put_bucket(data_structure,i,enc_bucket_src,enc_bucketSize);

        free(enc_bucket_src);
        free(bucket_src);
    }

    visitedOcallsWrite=0;
    visitedOcallsRead=0;

}

unsigned int Oram::RandomPath()
{
    unsigned char randomByte[1];
    sgx_read_rand(randomByte, 1);
    unsigned int randomInt[1];
    memcpy(randomInt, randomByte, sizeof(randomByte));
    return randomInt[0] % numBucketLeaf;
}

int Oram::GetNodeOnPath(unsigned int leaf, int curDepth) {
    leaf += bucketCount / 2;
    for (int d = depth - 1; d >= curDepth; d--) {
        leaf = (leaf + 1) / 2 - 1;
    }

    return leaf;
}


std::vector<Bid> Oram::GetIntersectingBlocks(int x, int curDepth) {
    std::vector<Bid> validBlocks;

    int node = GetNodeOnPath(x, curDepth);
    for (auto b : cache) {
        Bid bid = b.first;
        if (b.second != NULL && GetNodeOnPath(b.second->pos, curDepth) == node) {
            validBlocks.push_back(bid);
            if (validBlocks.size() >= Z) {
                return validBlocks;
            }
        }
    }
    return validBlocks;
}

void Oram::FetchPath(unsigned int leaf) {//
    
    readCnt++;
    unsigned char bucket_str_tmp[bucketSize]; //temp buffer for fetching bucket from ocall
    

    for (size_t d = 0; d <= depth; d++) {
        int node = GetNodeOnPath(leaf, d);
        //printf("FetchPath: calling bucket index(%d), depth(%d), leafPos (%d)\n", node,d,leaf);

        if (find(readviewmap.begin(), readviewmap.end(), node) != readviewmap.end()) {
            continue;
        } else {
            readviewmap.push_back(node);
        }

        //declare temp cipher and retrieve it from outside
        unsigned char* enc_bucket_str_tmp = (unsigned char*)malloc(enc_bucketSize);
        ocall_get_bucket(data_structure,node,enc_bucket_str_tmp,enc_bucketSize);

       
        visitedOcallsRead++;

        //decrypt the bucket here
        dec_aes_gcm(KC,enc_bucket_str_tmp,enc_bucketSize,bucket_str_tmp,bucketSize);
        
        //free memory of the enc_bucket_tmp
        free(enc_bucket_str_tmp);

        //deserealise bucket_str_tmp to Z AVLNodes 
        Node* tempNodes[Z]; //the number of nodes in a bucket
        deserialiseBucket(bucket_str_tmp,tempNodes);

        for (int i = 0; i < Z; i++) {
            //printf("Check node to cache (key: %s), (pos: %d), (lkey:%s), (lPos: %d) , (rKey: %s), (rPos: %d)\n",
            //        (char*)(tempNodes[i]->key.key),tempNodes[i]->pos, tempNodes[i]->leftID.key, tempNodes[i]->leftPos, tempNodes[i]->rightID.key, tempNodes[i]->rightPos);
            
            if (tempNodes[i]->key != empty_key) { // It isn't a dummy block   
                if (cache.count(tempNodes[i]->key) == 0) {
                    cache.insert(make_pair(tempNodes[i]->key, tempNodes[i]));
                } else { //it already exist
                    delete  tempNodes[i];
                }
            } else{ 
                    delete tempNodes[i];
            }
        }
    }
}

void Oram::deserialiseBucket(const unsigned char* bucket_str_tmp, Node* tempNodes[Z]){
           
    unsigned char* node_src1 = (unsigned char *) malloc( blockSize * sizeof(unsigned char));

    for(int v=0; v < Z;v++){   
        tempNodes[v] = new Node();
        memcpy(node_src1,bucket_str_tmp + (v*blockSize),blockSize);
        from_bytes1(node_src1,*(tempNodes[v])); 
    }

    free (node_src1);
}

void Oram::WritePath(unsigned int leaf,  int d) {

    int node = GetNodeOnPath(leaf, d);

    if (find(writeviewmap.begin(), writeviewmap.end(), node) == writeviewmap.end()) {

        unsigned char* bucket_src =  (unsigned char *) malloc( bucketSize * sizeof(unsigned char));
                       
        auto validBlocks = GetIntersectingBlocks(leaf, d);
        
        //printf("WritePath (bucketIndex %d): Valid block size %d, leafPos %d, depth_level %d\n", node, validBlocks.size(), leaf, d);


        unsigned char* temp_node_src = (unsigned char *) malloc( blockSize * sizeof(unsigned char));

        //fill up with real nodes
        for(int z=0; z < std::min((int)validBlocks.size(),Z); z++){

            Bid key_str = validBlocks[z];
            //printf("real node is key(%s), pos(%d), level(%d)\n", cache[key_str]->key.key, cache[key_str]->pos, cache[key_str]->height);
            to_bytes1(*(cache[key_str]),temp_node_src);

            //memcpy the node_src to the bucket_src
            memcpy(bucket_src + (z*blockSize), temp_node_src, blockSize);
            
            memset(temp_node_src, '0', ENTRY_HASH_KEY_LEN_128);
            
            //important to delete the pointer and cache here
            Node* curNode = cache[key_str];
            delete curNode;
            cache.erase(key_str);

        }

        //fill up with dummy nodes
        //printf("WritePath: Dummy block size %d, leafPos %d, depth_level %d\n", Z-validBlocks.size(), leaf, d);

        for(int z = validBlocks.size(); z < Z ; z++){
            memset(temp_node_src, '0', ENTRY_HASH_KEY_LEN_128);
            Node dummy_node;
            dummy_node.key = empty_key;

            to_bytes1(dummy_node,temp_node_src);

            //memcpy the node_src to the bucket_src
            memcpy(bucket_src + (z*blockSize), temp_node_src, blockSize);
        }

        //printf("start call outside");
        free (temp_node_src);

        // Write bucket to tree
        writeviewmap.push_back(node);

        //encrypt the bucket here before writing it to ocall
        unsigned char* enc_bucket_src = (unsigned char*) malloc(enc_bucketSize  * sizeof(unsigned char));
        enc_aes_gcm(KC,bucket_src,bucketSize,enc_bucket_src,enc_bucketSize);

        ocall_put_bucket(data_structure,node,enc_bucket_src,enc_bucketSize);
    
        visitedOcallsWrite++;


        free(enc_bucket_src);
        free(bucket_src);

        //printf("finish call outside");
    }
}


void Oram::Access(Bid bid, Node*& node, unsigned int lastLeaf, unsigned int newLeaf) {
    
    //printf("Cache size before Access %d", cache.size());

    FetchPath(lastLeaf);
    node = ReadData(bid);
    if (node != NULL) {
        node->pos = newLeaf;
        if (cache.count(bid) != 0) {
            cache.erase(bid);
        }
        cache[bid] = node;
        if (find(leafList.begin(), leafList.end(), lastLeaf) == leafList.end()) {
            leafList.push_back(lastLeaf);
        }
    }

    //printf("Cache size after Access %d", cache.size());
}

void Oram::Access(Bid bid, Node*& node) {
    
    //printf("Cache size before Access %d", cache.size());

    if (!batchWrite) {
        FetchPath(node->pos);
    }
    WriteData(bid, node);
    if (find(leafList.begin(), leafList.end(), node->pos) == leafList.end()) {
        leafList.push_back(node->pos);
    }

    //printf("Cache size after Access %d", cache.size());
}

Node* Oram::ReadNode(Bid bid) {
    if (bid == empty_key) {
        printf("ReadNode: Node is not set");
    }
    if (cache.count(bid) == 0) {
        printf("ReadNode: Node not found in the cache");
    } else {
        Node* node = cache[bid];
        return node;
    }
}

Node* Oram::ReadNode(Bid bid, int lastLeaf, int newLeaf) {
    if (bid == empty_key) {
        return NULL;
    }
    if (cache.count(bid) == 0 || find(leafList.begin(), leafList.end(), lastLeaf) == leafList.end()) {
        Node* node;
        Access(bid, node, lastLeaf, newLeaf);
        if (node != NULL) {
            modified.insert(bid);
        }
        //check for write only mode
        //if(isWriteOnly){
        //    detRead.insert(bid);
        //}
        return node;
    } else {
        modified.insert(bid);
        Node* node = cache[bid];
        node->pos = newLeaf;
        return node;
    }
}

int Oram::WriteNode(Bid bid, Node* node) {
    if (bid == empty_key) {
        printf("Node id is not set");
    }
    if (cache.count(bid) == 0) {
        modified.insert(bid);
        Access(bid, node);
        return node->pos;
    } else {
        modified.insert(bid);
        return node->pos;
    }
}

void Oram::finalise(bool find, Bid& rootKey, unsigned int& rootPos) {
    
    //fake read for padding     
    if (!batchWrite) {
        if (find) {
            for (unsigned int i = readCnt; i < depth * 1.45; i++) {
                int rnd = RandomPath();
                if (std::find(leafList.begin(), leafList.end(), rnd) == leafList.end()) {
                    leafList.push_back(rnd);
                }
                FetchPath(rnd);
            }
        } else {
            for (int i = readCnt; i < 4.35 * depth; i++) {
                int rnd = RandomPath();
                if (std::find(leafList.begin(), leafList.end(), rnd) == leafList.end()) {
                    leafList.push_back(rnd);
                }
                FetchPath(rnd);
            }
        }
    } 
    
   
    //updating the binary tree positions
    for (unsigned int i = 0; i <= depth + 2; i++) {
        for (auto t : cache) {
            if (t.second != NULL && t.second->height == i) {
                Node* tmp = t.second;
                if (modified.count(tmp->key)) {
                    tmp->pos = RandomPath();
                }
                if (tmp->leftID != empty_key && cache.count(tmp->leftID) > 0) {
                    tmp->leftPos = cache[tmp->leftID]->pos;
                }
                if (tmp->rightID != empty_key && cache.count(tmp->rightID) > 0) {
                    tmp->rightPos = cache[tmp->rightID]->pos;
                }
            }
        }
    }
    if (cache[rootKey] != NULL)
        rootPos = cache[rootKey]->pos;


    for (int d = depth; d >= 0; d--) {
        for (unsigned int i = 0; i < leafList.size(); i++) {
            WritePath(leafList[i], d);
        }
    }

    leafList.clear();
    modified.clear();

    printf("OcallWrite ( %d), ocallRead ( %d)", visitedOcallsWrite, visitedOcallsRead);

}

void Oram::start(bool batchWrite) {
    this->batchWrite = batchWrite;
    writeviewmap.clear();
    readviewmap.clear();
    readCnt = 0;

    visitedOcallsWrite=0;
    visitedOcallsRead=0;

}


void Oram::WriteData(Bid bid, Node* node) {
    cache[bid] = node;
}


Node* Oram::ReadData(Bid bid) {
    if (cache.find(bid) == cache.end()) {
        return NULL;
    }
    return cache[bid];
}


void Oram::to_bytes1( const Node& object, unsigned char* des){
    const unsigned char* begin = reinterpret_cast<const unsigned char*>(std::addressof(object));
    memcpy(des, begin, sizeof(Node));
}

void Oram::from_bytes1(const unsigned char* res, Node& object){
    unsigned char* begin_object = reinterpret_cast<unsigned char*> (std::addressof(object));
    memcpy(begin_object,res,sizeof(Node));
}


