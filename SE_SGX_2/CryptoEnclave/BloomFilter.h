#ifndef BLOOMFILTER_H
#define BLOOMFILTER_H

#include "../common/data_type.h"
#include <vector>

class BloomFilter{
    public:
        BloomFilter(uint64_t size, uint8_t numHashes);

        void add(const uint8_t *data, std::size_t len);
        bool possiblyContains(const uint8_t *data, std::size_t len) ;
       
    private:
        uint8_t m_numHashes;
        std::vector<bool> m_bits;

        std::array<uint64_t, 2> hash(const uint8_t *data,std::size_t len);
        uint64_t nthHash(uint8_t n, uint64_t hashA, uint64_t hashB, uint64_t filterSize);

};
 
#endif