#ifndef DATA_TYPE_2_H
#define DATA_TYPE_2_H

#include "config.h"
#include <stdint.h>
#include <vector>
#include <algorithm>
#include <array>
#include <list>
#include <string>
#include <tuple>
#include <utility>
#include <unordered_map>

//#define BUCKET_RAND_LEN 64 //
// #define BLOCK_RAND_LEN 16;
#define Z 4
//#define bSize 400
//using byte_t = unsigned char;
// using block = std::array<byte_t, BLOCK_RAND_LEN>;
// using BUCKET = std::vector<unsigned char>;
//#define maxBucketSize 512

typedef std::vector<unsigned char> BUCKET;

#define MAX_BUCKET_NUM 50000000

#endif
