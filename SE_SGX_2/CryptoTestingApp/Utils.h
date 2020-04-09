#ifndef UTILS_H
#define UTILS_H

#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <string.h>

#include "../common/data_type.h"
 
void handleErrors(void);

void print_bytes(uint8_t *ptr, uint32_t len);

int enc_aes_gcm(const unsigned char *plaintext, int plaintext_len,
                const unsigned char *key,
                unsigned char *ciphertext);

int dec_aes_gcm(unsigned char *ciphertext, int ciphertext_len,
                const unsigned char *key,
                unsigned char *plaintext);

#endif