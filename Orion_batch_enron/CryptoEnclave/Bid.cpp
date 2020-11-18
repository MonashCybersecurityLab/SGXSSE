#include "Bid.h"
#include "string.h"
#include <random>

Bid::Bid(){
    memset(key,'0',ENTRY_HASH_KEY_LEN_128);
}
Bid::Bid(const unsigned char *key_ptr){
    memcpy(key,key_ptr,ENTRY_HASH_KEY_LEN_128);
}
Bid::~Bid(){

}
Bid& Bid::operator=(const Bid as){
    memcpy(key,as.key,ENTRY_HASH_KEY_LEN_128);
    return *this;
}
Bid& Bid::operator=(const unsigned char *key_ptr){
    memcpy(key,key_ptr,ENTRY_HASH_KEY_LEN_128);
    return *this;
}

bool Bid::operator!=(const Bid as) const{
    int cmp_result = memcmp(key, as.key, ENTRY_HASH_KEY_LEN_128);
    if(cmp_result!=0)
    {
            return true;
    }
    return false;

}

bool Bid::operator==(const Bid as) const{
    int cmp_result = memcmp(key, as.key, ENTRY_HASH_KEY_LEN_128);
    if(cmp_result==0)
    {
            return true;
    }
    return false;
}

bool Bid::operator<(const Bid as) const{
    int comp_result = memcmp(key, as.key, ENTRY_HASH_KEY_LEN_128);
    if(comp_result <0){
        return true;
    }
    return false;
}

bool Bid::operator>(const Bid as) const{
    int comp_result= memcmp(key, as.key, ENTRY_HASH_KEY_LEN_128);
    if(comp_result > 0){
        return true;
    }
    return false;
}
