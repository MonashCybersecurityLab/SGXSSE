#include "BloomFilter.h"
#include "MurmurHash3.h"

//credited to http://blog.michaelschmatz.com/2016/04/11/how-to-write-a-bloom-filter-cpp/
//https://github.com/aappleby/smhasher/blob/master/src/MurmurHash3.h

//https://hur.st/bloomfilter/?n=100000&p=1.0E-6&m=&k=13
//https://drewdevault.com/2016/04/12/How-to-write-a-better-bloom-filter-in-C.html

BloomFilter::BloomFilter(uint64_t size, uint8_t numHashes){
    m_bits.resize(size);
    m_numHashes =  numHashes;
}

void BloomFilter::add(const uint8_t *data, std::size_t len) {
  auto hashValues = hash(data, len);

  for (int n = 0; n < m_numHashes; n++) {
      m_bits[nthHash(n, hashValues[0], hashValues[1], m_bits.size())] = true;
  }
}

bool BloomFilter::possiblyContains(const uint8_t *data, std::size_t len) {
  std::array<uint64_t, 2> hashValues = hash(data, len);

  for (int n = 0; n < m_numHashes; n++) {
      if (!m_bits[nthHash(n, hashValues[0], hashValues[1], m_bits.size())]) {
          return false;
      }
  }

  return true;
}

std::array<uint64_t, 2> BloomFilter::hash(const uint8_t *data,std::size_t len){
    std::array<uint64_t, 2> hashValue;
    MurmurHash3_x64_128(data, len, 0, hashValue.data());
    return hashValue;

}

inline uint64_t BloomFilter::nthHash(uint8_t n, uint64_t hashA, uint64_t hashB, uint64_t filterSize) {
    return (hashA + n * hashB) % filterSize;
}




