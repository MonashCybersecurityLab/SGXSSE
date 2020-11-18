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

//Enclave maintains the M_c
std::unordered_map<std::string,int> M_c;

/*** setup */
void ecall_init(unsigned char *keyF, size_t len){ 

    memcpy(KF,keyF,len);
    sgx_read_rand(KW, ENC_KEY_SIZE);
    sgx_read_rand(KC, ENC_KEY_SIZE);

    //init Bloom
    sgx_read_rand(K_BF, ENC_KEY_SIZE);
    
    //change reserver for M_C
    //uint64_t vector_size = 315000000;//hold up 15 mil k,v // about 40MB
    uint64_t vector_size = 460000000;//hold up 22 mil k,v // about 55MB
    //uint64_t vector_size = 830000000;//hold up 40 mil k,v // about 110MB
    
    uint8_t numHashs = 23;
    myBloomFilter = new BloomFilter(vector_size,numHashs);

    //reset M_c
    M_c.clear();
    M_c.reserve(22000000);
    printf("Max size of M_c %d\n", M_c.max_size());

}


//insertion
//std::string key2((char*)t2_u_arr[indexTest].content, t2_u_arr[indexTest].content_length);
//std::string value2((char*)t2_v_arr[indexTest].content, t2_v_arr[indexTest].content_length);
//M_c.insert(std::pair<std::string,std::string>(key2,value2));

//searching
//return M_c[u_prime_str];

//del Mc
//M_c.erase(del_u_prime);


/*** update with op=add */
void ecall_addDoc(char *doc_id, size_t id_length,char *content,int content_length){
              
    //parse content to keywords splited by comma
    std::vector<std::string> wordList;
    wordList = wordTokenize(content,content_length);
    size_t pair_no = wordList.size();

    rand_t t1_u_arr[pair_no];
    rand_t t1_v_arr[pair_no];

    int index=0;

    for(std::vector<std::string>::iterator it = wordList.begin(); it != wordList.end(); ++it) {
      
      std::string word = (*it);
    
      //printf("keyword %s", (char*)word.c_str());

      entryKey k_w;//, k_c;

      k_w.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + word.length(); 
	  k_w.content = (char *) malloc(k_w.content_length);
      enc_aes_gcm(KW,word.c_str(),word.length(),k_w.content,k_w.content_length);
    

      //k_c.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + word.length();
	  //k_c.content = (char *) malloc(k_c.content_length);
      //enc_aes_gcm(KC,word.c_str(),word.length(),k_c.content,k_c.content_length);

      //retrieve the state c    
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

      //generate F(k_w,id)content_length
      unsigned char *_u_prime = (unsigned char *) malloc(len * sizeof(unsigned char));
      hash_SHA128_key(k_w.content,k_w.content_length, doc_id,id_length,_u_prime);
    
      //convert the _u_prime to string, and store with c in M_c
      std::string c_key((char*)_u_prime, len);

      //printf("test len %d <-> %s",len,(char*)_u_prime);
      M_c.insert(std::pair<std::string,int>(c_key,c));

       
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

      //free k_w
      free(k_w.content);

      //free value
      free(message);

      //free memory for BF
      free(m);
      free(m_prime);

    }

    //call Server to update
    ocall_transfer_encrypted_entries(t1_u_arr,
                                     t1_v_arr,
                                     pair_no, sizeof(rand_t));

}

/*** update with op=del */
void ecall_delDoc(char *doc_id, size_t id_length){
    std::string delId(doc_id,id_length);
    d.push_back(delId);

    //add dummy [rand] entries to M_I based on r
    
    //int r;
    //sgx_read_rand((unsigned char *)&r, sizeof(int));
    //r=r%RAND_LEN;

    rand_t t1_u_arr[6];
    rand_t t1_v_arr[6];

    //printf("come  here2");
    //unsigned char label[RAND_LEN] = {0};
    //unsigned char value[RAND_LEN] = {0};

    int index=0;

    for(int index=0;index< 6; index++){
        //generate a pair (u,v)
        sgx_read_rand(t1_u_arr[index].content, RAND_LEN);
        t1_u_arr[index].content_length = RAND_LEN;

        sgx_read_rand(t1_v_arr[index].content, RAND_LEN);
        t1_v_arr[index].content_length = RAND_LEN;

    }

    //call Server to update
    ocall_transfer_encrypted_entries(t1_u_arr,
                                     t1_v_arr,
                                     6, sizeof(rand_t));
      

}

/*** search for a keyword */
void ecall_search(const char *keyword, size_t keyword_len){

    //init keys
    std::string keyword_str(keyword,keyword_len);

    //printf("Mc size %d",M_c.size());

    entryKey k_w;//, k_c;

    k_w.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + keyword_len; 
	k_w.content = (char *) malloc(k_w.content_length);
    enc_aes_gcm(KW,keyword,keyword_len,k_w.content,k_w.content_length);
    

    //k_c.content_length = AESGCM_MAC_SIZE + AESGCM_IV_SIZE + keyword_len; 
	//k_c.content = (char *) malloc(k_c.content_length);
    //enc_aes_gcm(KC,keyword,keyword_len,k_c.content,k_c.content_length);

    //retrieve the latest state of the keyword 
    int w_c_max=0;
    std::unordered_map<std::string,int>::const_iterator got = ST.find(keyword_str);
    if ( got == ST.end()) {
        printf("Keyword is not existed for search");
        return;
    }else{
        w_c_max = got->second;
    }

    //printf("c max value  [1-c] %d\n",  w_c_max);

    //init st_w_c and Q_w
    std::vector<int> st_w_c;
    for(int i_c = 1; i_c <= w_c_max;i_c++)
            st_w_c.push_back(i_c);

    std::vector<int> st_w_c_difference;

    //printf("deleted list size %d\n",d.size());

    size_t _u_prime_size = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    unsigned char *_u_prime = (unsigned char *) malloc(_u_prime_size * sizeof(unsigned char));


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
            
            //convert the _u_prime to string, and store with c in M_c
            std::string c_key((char*)_u_prime, _u_prime_size);

            int temp = M_c[c_key];
            st_w_c_difference.push_back(temp);
            
            //delete I_c by ocall (delete later by batch ???)
            //ocall_del_M_c_value(_u_prime,_u_prime_size);      

            //reset
            memset(_u_prime, 0, _u_prime_size * sizeof(unsigned char));

        }

          //free memory
        free(m);
        free(m_prime);   

    }

    //free memory 
    free(_u_prime);


    std::vector<int> merged_st;

    std::set_difference(st_w_c.begin(),st_w_c.end(),
                        st_w_c_difference.begin(),st_w_c_difference.end(),
                        std::back_inserter(merged_st));

    //printf("----");
    size_t pair_no = merged_st.size();
    //printf("No. of non-deleted ids %d",pair_no);

    //declare query tokens for ocall

    //need to do in batch later
    //rand_t Q_w_u_arr[pair_no];
    //rand_t Q_w_id_arr[pair_no];
    
   
    
    //without batch, send one-by-one ocall
    /***

    //int index=0;

    size_t len = ENTRY_HASH_KEY_LEN_128 + k_w.content_length;
    unsigned char *k_id =  (unsigned char *) malloc(ENTRY_HASH_KEY_LEN_128); 

    for (int j=0; j< pair_no; j++) { 

        rand_t Q_w_u_arr[1];
        rand_t Q_w_id_arr[1];

        //generate u token H2(k_w,c)
        std::string c_str = std::to_string(merged_st[j]);
        char const *c_char = c_str.c_str();

        //printf("Non-deleted states %s",c_char);

        unsigned char *_u = (unsigned char *) malloc(len * sizeof(unsigned char));
        hash_SHA128_key(k_w.content,k_w.content_length, c_char,c_str.length(),_u);
    
        memcpy(&Q_w_u_arr[0].content,_u,len);
        Q_w_u_arr[0].content_length = len;

        //generate k_id based on c
        hash_SHA128(k_w.content,c_char,c_str.length(),k_id);
        
        memcpy(&Q_w_id_arr[0].content,k_id,ENTRY_HASH_KEY_LEN_128);
        Q_w_id_arr[0].content_length = ENTRY_HASH_KEY_LEN_128;

        //index++;

        //reset k_id
        memset(k_id, 0, ENTRY_HASH_KEY_LEN_128 * sizeof(unsigned char));
        
        //free memory
        free(_u);

        ocall_query_tokens_entries(Q_w_u_arr,
                               Q_w_id_arr,
                               1, sizeof(rand_t));
    }

    free(k_id);


    //free memory
    free(k_w.content);

    //send Q_w to Server
    //ocall_query_tokens_entries(Q_w_u_arr,
    //                           Q_w_id_arr,
    //                           pair_no, sizeof(rand_t));


    ***/

     //send in batch of 10,000

    
    int batch = pair_no / BATCH_SIZE;

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
    
    free(Q_w_u_arr);
    free(Q_w_id_arr);


 
}
