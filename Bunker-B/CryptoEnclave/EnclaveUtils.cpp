#include "EnclaveUtils.h"
#include "CryptoEnclave_t.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "../common/data_type.h"

void printf( const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}
void print_bytes(uint8_t *ptr, uint32_t len) {
  for (uint32_t i = 0; i < len; i++) {
    printf("%x", *(ptr + i));
  }

  printf("\n");
}


//int result = cmp((const uint8_t *)gcm_iv,(const uint8_t *)gcm_iv,AESGCM_IV_SIZE);
//printf("test%d\n",result);
int  cmp(const uint8_t *value1, const uint8_t *value2, uint32_t len){
    for (uint32_t i = 0; i < len; i++) {
        if (*(value1+i) != *(value2+i)) {
        return -1;
        }
    }

    return 0;
}

void  clear(uint8_t *dest, uint32_t len){
    for (uint32_t i = 0; i < len; i++) {
        *(dest + i) = 0;
    }
}

std::vector<std::string>  wordTokenize(char *content,int content_length){
    

    char delim[] = ",";//" ,.-";
    std::vector<std::string> result;

    char *token = strtok(content,delim);
    while (token != NULL)
    {
        result.push_back(token); 
        token =  strtok(NULL,delim);
    }

/***
    for (std::string i; ss >> i;) {
        result.push_back(i);    
        if (ss.peek() == ',')
            ss.ignore();
    } */

    return result;
}

//PRF

entryKey prf_F(const void *key,const void *plaintext,size_t plaintext_len){
    entryKey k;

    size_t cipher_len = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + plaintext_len; //important- has to be size_t
	unsigned char *ciphertext = (unsigned char *) malloc(cipher_len); 
	enc_aes_gcm(key,plaintext,plaintext_len,ciphertext);
    
    k.content = ciphertext;
    k.content_length = cipher_len;

    return k;
}

void prf_F_improve(const void *key,const void *plaintext,size_t plaintext_len, rand_t *value) {
	value->content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + plaintext_len; //important- has to be size_t
	enc_aes_gcm(key, plaintext, plaintext_len, value->content);
}

entryValue prf_Enc(const void *key,const void *plaintext,size_t plaintext_len) {
    entryValue v;

    size_t cipher_len = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + plaintext_len; //important- has to be size_t
	unsigned char *ciphertext = (unsigned char *) malloc(cipher_len); 
	enc_aes_gcm(key,plaintext,plaintext_len,ciphertext);
    
    v.message = (char*) ciphertext;
    v.message_length = cipher_len;

    return v;
}

void prf_Enc_improve(const void *key,const void *plaintext,size_t plaintext_len, rand_t *value) {
    value->content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + plaintext_len; //important- has to be size_t
	enc_aes_gcm(key, plaintext, plaintext_len, value->content);
}

entryValue prf_Dec(const void *key,const void *ciphertext,size_t ciphertext_len){
    entryValue value;

    size_t decMessageLen = ciphertext_len - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
	unsigned char *decMessage = (unsigned char *) malloc(decMessageLen); 
    dec_aes_gcm(key,ciphertext,ciphertext_len,decMessage,decMessageLen);

    value.message = (char*)decMessage;
    value.message_length = decMessageLen;

    return value;
}

void prf_Dec_improve(const void *key,const void *ciphertext,size_t ciphertext_len, rand_t *value) {
	value->content_length = ciphertext_len - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
    dec_aes_gcm(key, ciphertext, ciphertext_len, value->content, value->content_length);
}

void enc_aes_gcm(const void *key, const void *plaintext, size_t plaintext_len, void *ciphertext)
{
  //uint8_t p_dst[ciphertext_len] = {0};

  //p_dst = mac + iv + cipher
	sgx_rijndael128GCM_encrypt(
    (sgx_aes_gcm_128bit_key_t*)key,
		(uint8_t *) plaintext, plaintext_len,
		(uint8_t *) (ciphertext + AESGCM_MAC_SIZE + AESGCM_IV_SIZE), //where  the cipher should be stored
		(uint8_t *)gcm_iv, AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) ciphertext);	//the tag should be the first 16 bytes and auto dumped out

  memcpy(ciphertext + AESGCM_MAC_SIZE, gcm_iv, AESGCM_IV_SIZE);

  //copy tag+iv+cipher to ciphertext
  //memcpy(ciphertext, p_dst, ciphertext_len);

  //printf("test\n");
  //print_bytes((uint8_t *) plaintext,(uint32_t) plaintext_len);
}

void dec_aes_gcm(const void *key, const void *ciphertext, size_t ciphertext_len, void *plaintext, size_t plaintext_len){
    
    //uint8_t p_dst[plaintext_len] = {0};

	sgx_status_t ret = sgx_rijndael128GCM_decrypt(
		(sgx_aes_gcm_128bit_key_t*)key,//,&key, //*WARNING FOR TEXT PURPOSE ONLY-USE KF *********WARNING FOR TEST PURPOSE 
		(uint8_t *) (ciphertext + AESGCM_MAC_SIZE + AESGCM_IV_SIZE), plaintext_len,
		(uint8_t *) plaintext,
		(uint8_t *)gcm_iv, AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) ciphertext); //get the first 16 bit tag to verify

	//memcpy(plaintext, p_dst, plaintext_len);

  //printf("test\n");
  //print_bytes((uint8_t *) plaintext,(uint32_t) plaintext_len);
}
