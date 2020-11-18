#ifndef BID_H
#define BID_H

#include "../common/data_type.h"

class Bid
{

public:
    unsigned char key[ENTRY_HASH_KEY_LEN_128];
    Bid();
    Bid(const unsigned char *key_ptr);
    ~Bid();
    Bid& operator=(const Bid as);
    Bid& operator=(const unsigned char *key_ptr);
    bool operator!=(const Bid as) const;
    bool operator==(const Bid as) const;
    bool operator<(const Bid as) const;
    bool operator>(const Bid as) const;
};

#endif