#include "CryptoEnclave_t.h"

#include "EnclaveUtils.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <vector>
#include <list>
#include "../common/data_type.h"
#include "BloomFilter.h"


//change to malloc for tokens , run ulimit -s 65536 to set stack size to
//65536 KB in linux

// local variables inside Enclave
unsigned char KW[ENC_KEY_SIZE] = {0};
unsigned char KC[ENC_KEY_SIZE] = {0};
unsigned char KF[ENC_KEY_SIZE] = {0};

//generate key for BF
unsigned char K_BF[ENC_KEY_SIZE] = {0};
BloomFilter *myBloomFilter;

std::unordered_map<std::string, int> ST;
//std::unordered_map<std::string, std::vector<std::string>> D;

std::vector<std::string> d;

/*** setup */
void ecall_init(unsigned char *keyF, size_t len){ 

    memcpy(KF,keyF,len);
    sgx_read_rand(KW, ENC_KEY_SIZE);
    sgx_read_rand(KC, ENC_KEY_SIZE);

    //init Bloom
    sgx_read_rand(K_BF, ENC_KEY_SIZE);
    uint64_t vector_size = 35000000;//4mb hold up to 1.5 million key,value pairs
    uint8_t numHashs = 23;
    myBloomFilter = new BloomFilter(vector_size,numHashs);

}

/*** update with op=add */
void ecall_addDoc(char *doc_id, size_t id_length,char *content,int content_length){
              
    //parse content to keywords splited by comma
    std::vector<std::string> wordList;
    wordList = wordTokenize(content,content_length);
    size_t pair_no = wordList.size();

    rand_t t1_u_arr[pair_no];
    rand_t t1_v_arr[pair_no];
    rand_t t2_u_arr[pair_no];
    rand_t t2_v_arr[pair_no];

    int index=0;

    for(std::vector<std::string>::iterator it = wordList.begin(); it != wordList.end(); ++it) {
      
      std::string word = (*it);
    
      //printf("keyword %s", (char*)word.c_str());

      entryKey k_w, k_c;

      k_w.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + word.length(); 
	  k_w.content = (char *) malloc(k_w.content_length);
      enc_aes_gcm(KW,word.c_str(),word.length(),k_w.content,k_w.content_length);
    

      k_c.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + word.length();
	  k_c.content = (char *) malloc(k_c.content_length);
      enc_aes_gcm(KC,word.c_str(),word.length(),k_c.content,k_c.content_length);
          
      int c=0;

      std::unordered_map<std::string,int>::const_iterator got = ST.find(word);
      if ( got == ST.end()) {
          c = 0;  
      }else{
        c = got->second;
      }
      c++;

      //printf("State c: %d \n", c);

      //find k_id
      unsigned char *k_id =  (unsigned char *) malloc(ENTRY_HASH_KEY_LEN_128); 
      std::string c_str = std::to_string(c);
      char const *c_char = c_str.c_str();
      hash_SHA128(k_w.content,c_char,c_str.length(),k_id);

      //len is used for hash_SHA128_key multiple times
      size_t len = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
      
      //generate a pair (u,v)
      unsigned char *_u = (unsigned char *) malloc(len * sizeof(unsigned char));
      hash_SHA128_key(k_w.content,k_w.content_length, c_char,c_str.length(),_u);
      memcpy(&t1_u_arr[index].content,_u,len);
      t1_u_arr[index].content_length = len;


      size_t message_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + id_length;
      char* message = (char *) malloc(message_length);
        
      enc_aes_gcm(k_id,doc_id,id_length,message,message_length);
      memcpy(&t1_v_arr[index].content,(unsigned char*)message,message_length);
      t1_v_arr[index].content_length = message_length;

      //generate a pair (u',v')
      unsigned char *_u_prime = (unsigned char *) malloc(len * sizeof(unsigned char));
      hash_SHA128_key(k_w.content,k_w.content_length, doc_id,id_length,_u_prime);
      memcpy(&t2_u_arr[index].content,_u_prime,len);
      t2_u_arr[index].content_length = len;

      size_t message_length2 = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + c_str.length();
      char* message2 = (char *) malloc(message_length2);

      enc_aes_gcm(k_c.content,c_char,c_str.length(),message2,message_length2);
      memcpy(&t2_v_arr[index].content,(unsigned char*)message2,message_length2);
      t2_v_arr[index].content_length = message_length2;

      //update ST
      got = ST.find(word);
      if( got == ST.end()){
          ST.insert(std::pair<std::string,int>(word,c));
      } else{
          ST.at(word) = c;
      }

      index++;

      //update bloom filter
      size_t m_len = (k_w.content_length + id_length);
      unsigned char *m =  (unsigned char *) malloc( m_len * sizeof(unsigned char));  
      memcpy(m,(unsigned char*)k_w.content,k_w.content_length);
      memcpy(m+k_w.content_length,(unsigned char*)doc_id,id_length);
      size_t len2 = ENTRY_HASH_KEY_LEN_128 + ENC_KEY_SIZE;
      unsigned char *m_prime = (unsigned char *) malloc(len2 * sizeof(unsigned char));
      hash_SHA128_key(K_BF,ENC_KEY_SIZE, m,m_len,m_prime);

      myBloomFilter->add((uint8_t*)m_prime,len2);
      
      //free memory
      free(k_id);
      free(_u);
      free(_u_prime);

      //free k_w, k_c
      free(k_w.content);
      free(k_c.content);

      //free value
      free(message);
      free(message2);


      //free memory for BF
      free(m);
      free(m_prime);

    }

    //call Server to update
    ocall_transfer_encrypted_entries(t1_u_arr,
                                     t1_v_arr,
                                     t2_u_arr,
                                     t2_v_arr,
                                     pair_no, sizeof(rand_t));

}

/*** update with op=del */
void ecall_delDoc(char *doc_id, size_t id_length){
    std::string delId(doc_id,id_length);
    d.push_back(delId);
}

/*** search for a keyword */
void ecall_search(const char *keyword, size_t keyword_len){

    //init keys
    std::string keyword_str(keyword,keyword_len);

    entryKey k_w, k_c;

    k_w.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + keyword_len; 
	k_w.content = (char *) malloc(k_w.content_length);
    enc_aes_gcm(KW,keyword,keyword_len,k_w.content,k_w.content_length);
    

    k_c.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + keyword_len; 
	k_c.content = (char *) malloc(k_c.content_length);
    enc_aes_gcm(KC,keyword,keyword_len,k_c.content,k_c.content_length);

    //retrieve the latest state of the keyword 
    int w_c_max=0;
    std::unordered_map<std::string,int>::const_iterator got = ST.find(keyword_str);
    if ( got == ST.end()) {
        printf("Keyword is not existed for search");
        return;
    }else{
        w_c_max = got->second;
    }

    //printf("c max value [1-c] %d\n", w_c_max);

    //init st_w_c and Q_w
    std::vector<int> st_w_c;
    for(int i_c = 1; i_c <= w_c_max;i_c++)
            st_w_c.push_back(i_c);

    std::vector<int> st_w_c_difference;

    //printf("deleted list size %d\n",d.size());

    size_t _u_prime_size = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    unsigned char *_u_prime = (unsigned char *) malloc(_u_prime_size * sizeof(unsigned char));
    unsigned char *_v_prime = (unsigned char *) malloc(ENTRY_VALUE_LEN * sizeof(unsigned char));
    int _v_prime_size;

    //loop through id_i in d
    for(auto&& del_id: d){

        //test H(k_BF, w||id)
        size_t m_len = (k_w.content_length + del_id.size());
        unsigned char *m =  (unsigned char *) malloc( m_len * sizeof(unsigned char));  
        memcpy(m,(unsigned char*)k_w.content,k_w.content_length);
        memcpy(m+k_w.content_length,(unsigned char*)del_id.c_str(),del_id.size());

        size_t len2 = ENTRY_HASH_KEY_LEN_128 + ENC_KEY_SIZE;
        unsigned char *m_prime = (unsigned char *) malloc(len2 * sizeof(unsigned char));
        hash_SHA128_key(K_BF,ENC_KEY_SIZE, m,m_len,m_prime);

        //it come heres
        //print_bytes((uint8_t*)m_prime,(uint32_t)len2);

         //check bloom filter
        if(myBloomFilter->possiblyContains((uint8_t*)m_prime,len2)){
            
            //retrieve a pair (u',v')
            hash_SHA128_key(k_w.content,k_w.content_length, (unsigned char*)del_id.c_str(),del_id.size(),_u_prime);
             
            ocall_retrieve_M_c(_u_prime,_u_prime_size * sizeof(unsigned char),
                                     _v_prime,ENTRY_VALUE_LEN * sizeof(unsigned char),
                                     &_v_prime_size,sizeof(int));
            

            size_t c_value_len = (size_t)_v_prime_size - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;
	        unsigned char *c_value_content = (unsigned char *) malloc(c_value_len* sizeof(unsigned char)); 
            dec_aes_gcm(k_c.content,_v_prime,_v_prime_size,
                    c_value_content,c_value_len);
            
            //printf(">%s",(char*)del_id.c_str());
            //printf("deleted counter %s", (char*)c_value_content);

            //print_bytes((uint8_t*)c_value_content,(uint32_t)c_value_len);
            std::string c_str1((char*)c_value_content,c_value_len);

            int temp = std::stoi(c_str1);
            st_w_c_difference.push_back(temp);
            
            //delete I_c by ocall (delete later by batch ???)
            //ocall_del_M_c_value(_u_prime,_u_prime_size);      

            //reset
            memset(_u_prime, 0, _u_prime_size * sizeof(unsigned char));
            memset(_v_prime, 0, ENTRY_VALUE_LEN * sizeof(unsigned char));
            _v_prime_size = 0;

            //free memory
            free(c_value_content);
        }

          //free memory
        free(m);
        free(m_prime);   

    }

    //free memory 
    free(_u_prime);
    free(_v_prime);

    std::vector<int> merged_st;

    std::set_difference(st_w_c.begin(),st_w_c.end(),
                        st_w_c_difference.begin(),st_w_c_difference.end(),
                        std::back_inserter(merged_st));

    //printf("----");
    size_t pair_no = merged_st.size();
    printf("No. of non-deleted ids %d",pair_no);

    //declare query tokens for ocall
    rand_t Q_w_u_arr[pair_no];
    rand_t Q_w_id_arr[pair_no];
    
    int index=0;

    size_t len = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    unsigned char *k_id =  (unsigned char *) malloc(ENTRY_HASH_KEY_LEN_128); 

    for (int j=0; j< pair_no; j++) { 

        //generate u token H2(k_w,c)
        std::string c_str = std::to_string(merged_st[j]);
        char const *c_char = c_str.c_str();

        //printf("Non-deleted states %s",c_char);

        unsigned char *_u = (unsigned char *) malloc(len * sizeof(unsigned char));
        hash_SHA128_key(k_w.content,k_w.content_length, c_char,c_str.length(),_u);
    
        memcpy(&Q_w_u_arr[index].content,_u,len);
        Q_w_u_arr[index].content_length = len;

        //generate k_id based on c
        hash_SHA128(k_w.content,c_char,c_str.length(),k_id);
        
        memcpy(&Q_w_id_arr[index].content,k_id,ENTRY_HASH_KEY_LEN_128);
        Q_w_id_arr[index].content_length = ENTRY_HASH_KEY_LEN_128;

        index++;

        //reset k_id
        memset(k_id, 0, ENTRY_HASH_KEY_LEN_128 * sizeof(unsigned char));
        
        //free memory
        free(_u);
    }

    free(k_id);


    //free memory
    free(k_w.content);
    free(k_c.content);

    //send Q_w to Server
    ocall_query_tokens_entries(Q_w_u_arr,
                               Q_w_id_arr,
                               pair_no, sizeof(rand_t));

 
}
