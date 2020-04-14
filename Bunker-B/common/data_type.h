#ifndef DATA_TYPE_H
#define DATA_TYPE_H

#include "config.h"
#include <stdint.h>

#include <algorithm>
#include <array>
#include <list>
#include <string>
#include <tuple>
#include <utility>
#include <unordered_map>

/* for all sources except OCALL/ECALL */

const std::string raw_doc_dir= "streaming/";
//const std::string enc_doc_dir= "enc_doc/";

#define AESGCM_IV_SIZE 12
static unsigned char gcm_iv[] = {
    0x99, 0xaa, 0x3e, 0x68, 0xed, 0x81, 0x73, 0xa0, 0xee, 0xd0, 0x66, 0x84
};

#define AESGCM_MAC_SIZE 16

#define MAX_FILE_LENGTH 10 //10 bytes
#define ENC_KEY_SIZE 16 //16 bytes for AES128
#define ENTRY_VALUE_LEN 128 // 1024-bit

#define ENTRY_HASH_KEY_LEN_128 16 // for HMAC-SHA128- bit key
//#define ENTRY_HASH_KEY_LEN_256 32 // for HMAC-SHA128- bit key

#define BUFLEN 2048 //buffer for enc + dec

/*** 
#if !defined(ARRAY_SIZE)
    #define ARRAY_SIZE(x) (sizeof((x)) / sizeof((x)[0]))
#endif
 */

#define RAND_LEN 64 // 2048-bit

const int DEL = 0;
const int ADD = 1;

typedef struct
{
    size_t content_length;
    unsigned char content[RAND_LEN];
} rand_t; //used to export between ecall and ocall

/* packet related */
typedef struct docIds {
    char *doc_id; 
    size_t id_length;  // length of the doc_id
} docId; 

/* define an entry key-value pair, key is default with a fixed size*/
//typedef std::array<char, ENTRY_HASH_KEY_LEN> entry_fixed_key;

typedef struct entryKeys {
    unsigned char *content;
    size_t content_length;  // length of the entry_value
} entryKey;

typedef struct entryStates {    // ST set
    int version;
    int count;
} entryState;

typedef struct entryValues {
    char *message; 
    size_t message_length;  // length of the entry_value
} entryValue;

typedef struct docContents{
    docId id;
    char* content;
    int content_length;
} docContent;

typedef std::pair<entryKey, entryValue> entry;

#endif
