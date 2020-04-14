#ifndef ENCLAVE_UTILS_H
#define ENCLAVE_UTILS_H

#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <iterator>
#include <vector>
#include <cstring>
#include "../common/data_type.h"


void printf( const char *fmt, ...);
void print_bytes(uint8_t *ptr, uint32_t len);
int  cmp(const uint8_t *value1, const uint8_t *value2, uint32_t len);
void clear(uint8_t *dest, uint32_t len);
std::vector<std::string>  wordTokenize(char *content,int content_length);


entryKey prf_F(const void *key,const void *plaintext,size_t plaintext_len);
void prf_F_improve(const void *key,const void *plaintext,size_t plaintext_len, rand_t *value);

entryValue prf_Enc(const void *key,const void *plaintext,size_t plaintext_len);
void prf_Enc_improve(const void *key,const void *plaintext,size_t plaintext_len, rand_t *value);
entryValue prf_Dec(const void *key,const void *ciphertext,size_t ciphertext_len);
void prf_Dec_improve(const void *key,const void *ciphertext,size_t ciphertext_len, rand_t *value);

void enc_aes_gcm(const void *key, const void *plaintext, size_t plaintext_len, void *ciphertext);
void dec_aes_gcm(const void *key, const void *ciphertext, size_t ciphertext_len, void *plaintext, size_t plaintext_len);

#endif
