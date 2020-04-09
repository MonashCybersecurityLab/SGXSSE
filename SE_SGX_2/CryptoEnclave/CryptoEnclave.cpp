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

// change to malloc for tokens, run ulimit -s 65536 to set stack size to 
// 65536 KB in linux 

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
    uint64_t vector_size = 35000000;//4mb;//hold up to 1.5 million key,value pairs;
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
      hash_SHA128_key(K_BF,ENC_KEY_SIZE, m, m_len, m_prime);

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

      //free bloom filter
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

    //printf("c max value [1-c] %d", w_c_max);

    //init st_w_c and Q_w
    std::vector<int> st_w_c;
    for(int i_c = 1; i_c <= w_c_max;i_c++)
            st_w_c.push_back(i_c);

    std::vector<int> st_w_c_difference;

    int batch = d.size() / BATCH_SIZE;
   
    size_t _u_prime_size = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    rand_t _u_prime[BATCH_SIZE];
    v _v_prime[BATCH_SIZE];
    int _v_prime_size;


    for(int i = 0; i <= batch; i++) {
    	// determine the largest sequence no. in the current batch
    	int limit = BATCH_SIZE * (i + 1) > d.size() ? d.size() : BATCH_SIZE * (i + 1);

    	// determine the # of tokens in the current batch
    	int length = BATCH_SIZE * (i + 1) > d.size() ? d.size() - BATCH_SIZE * i : BATCH_SIZE;

        int counter = 0;
        int v_size = 0;
    	//test H(k_BF, w||id)
        for(int j = BATCH_SIZE * i; j < limit; j++) {
        	size_t m_len = (k_w.content_length + d[j].size());
        	unsigned char *m =  (unsigned char *) malloc( m_len * sizeof(unsigned char));
            memcpy(m,(unsigned char*)k_w.content,k_w.content_length);
     	    size_t len2 = ENTRY_HASH_KEY_LEN_128 + ENC_KEY_SIZE;
            unsigned char *m_prime = (unsigned char *) malloc(len2 * sizeof(unsigned char));
        	memcpy(m+k_w.content_length,(unsigned char*)d[j].c_str(),d[j].size());

            hash_SHA128_key(K_BF,ENC_KEY_SIZE, m,m_len,m_prime);
            //check bloom filter
            if(myBloomFilter->possiblyContains((uint8_t*)m_prime,len2)){
            	//retrieve a pair (u',v')
            	_u_prime[counter].content_length = _u_prime_size;
                hash_SHA128_key(k_w.content,k_w.content_length, (unsigned char*)d[j].c_str(),d[j].size()
                		,_u_prime[counter].content);
                counter++;
            }

            //free memory
            free(m);
            free(m_prime);
        }


        if(counter > 0) {
        	ocall_retrieve_M_c(_u_prime, sizeof(rand_t), _v_prime, sizeof(v)
        			, counter, &v_size, sizeof(int));
        	for(int j = 0; j < v_size; j++) {
        		size_t c_value_len = _v_prime[j].content_length - AESGCM_MAC_SIZE - AESGCM_IV_SIZE;

        	    unsigned char c_value_content[c_value_len];
        	    dec_aes_gcm(k_c.content,_v_prime[j].content, _v_prime[j].content_length,
        	    		c_value_content,c_value_len);

        	    //print_bytes((uint8_t*)c_value_content,(uint32_t)c_value_len);
        	    std::string c_str1((char*)c_value_content,c_value_len);

        	    int temp = std::stoi(c_str1);
        	    //st_w_c.erasej);
        	    st_w_c_difference.push_back(temp);
        	    //free memory
        	     //free(c_value_content);
        	 }
        }
    }

    std::vector<int> merged_st;

    std::set_difference(st_w_c.begin(), st_w_c.end(),
    		st_w_c_difference.begin(), st_w_c_difference.end(),
			std::back_inserter(merged_st));

    //free memory 
    //free(_u_prime);
    //free(_v_prime);

    //printf("----");
    size_t pair_no = merged_st.size();

    //declare query tokens for ocall

    batch = pair_no / BATCH_SIZE;

    rand_t *Q_w_u_arr = (rand_t *) malloc(BATCH_SIZE * sizeof(rand_t));
    rand_t *Q_w_id_arr = (rand_t *) malloc(BATCH_SIZE * sizeof(rand_t));
    
    int index=0;

    size_t len = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    unsigned char *k_id =  (unsigned char *) malloc(ENTRY_HASH_KEY_LEN_128); 

    // do batch process
    for(int i = 0; i <= batch; i++) {
	// determine the largest sequence no. in the current batch
	int limit = BATCH_SIZE * (i + 1) > pair_no ? pair_no : BATCH_SIZE * (i + 1);

	// determine the # of tokens in the current batch
	int length = BATCH_SIZE * (i + 1) > pair_no ? pair_no - BATCH_SIZE * i : BATCH_SIZE;

	for(int j = BATCH_SIZE * i; j < limit; j++) {
	    //generate u token H2(k_w,c)
        std::string c_str = std::to_string(merged_st[j]);
        char const *c_char = c_str.c_str();
	    
	    unsigned char *_u = (unsigned char *) malloc(len * sizeof(unsigned char));
        hash_SHA128_key(k_w.content,k_w.content_length, c_char,c_str.length(),_u);

	    memcpy(Q_w_u_arr[j - BATCH_SIZE * i].content,_u,len);
        Q_w_u_arr[j - BATCH_SIZE * i].content_length = len;

	    //generate k_id based on c
        hash_SHA128(k_w.content,c_char,c_str.length(),k_id);
	    
        memcpy(Q_w_id_arr[j - BATCH_SIZE * i].content, k_id, ENTRY_HASH_KEY_LEN_128);
        Q_w_id_arr[j - BATCH_SIZE * i].content_length = ENTRY_HASH_KEY_LEN_128;

	    //reset k_id
        memset(k_id, 0, ENTRY_HASH_KEY_LEN_128 * sizeof(unsigned char));
        
        //free memory
        free(_u);
	}
	//printf("ocall");
	//send Q_w to Server
    ocall_query_tokens_entries(Q_w_u_arr,
                               Q_w_id_arr,
                               length, sizeof(rand_t));
	//printf("ocalled");
		
    }

    free(k_id);


    //free memory
    free(k_w.content);
    free(k_c.content);

    free(Q_w_u_arr);
    free(Q_w_id_arr);
}
