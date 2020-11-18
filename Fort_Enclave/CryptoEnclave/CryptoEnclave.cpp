#include "CryptoEnclave_t.h"

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


//change to malloc for tokens , run ulimit -s 65536 to set stack size to
//65536 KB in linux


//unsigned long long no_stash_del_entries  = 1000000;
//unsigned long long no_w_delete_proportion = 5; //%

std::vector<std::string> stash_del;
std::vector<std::string> w_del_tokens;

void printf( const char *fmt, ...)
{
    char buf[BUFSIZ] = {'\0'};
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
}

/*** setup */
void ecall_init(unsigned int stash_del_size, unsigned int w_delete_token_size){ 
   

    //print the size of w_del_tokens
    //printf("Stash del size %d, w_delete_token_size %d\n", stash_del_size, w_delete_token_size );

    unsigned char label[ENC_KEY_SIZE] = {0};
   
    for(unsigned int counter= 1; counter <= stash_del_size; counter++){
            sgx_read_rand(label, ENC_KEY_SIZE);
            std::string str_label((char*)label, ENC_KEY_SIZE);

            stash_del.push_back(str_label);
            if(counter > stash_del_size - w_delete_token_size){
                    //also randomly push into the generated deleted of w based on w_delete_token_size
                w_del_tokens.push_back(str_label);
            }
    }

    //print the size of w_del_tokens
    //printf("Deleted tokens of w %d\n", w_del_tokens.size());
}

void ecall_scan(){ 

    //reset counter
    unsigned int counter= 0;

    //then loop the stash_del again to find out
    for(std::vector<std::string>::iterator it = w_del_tokens.begin(); it != w_del_tokens.end(); ++it) {
      
            std::string cur_del_token = (*it);
            //check the token against the stash_del
            //if found just increase counter by 1
            if(std::find(stash_del.begin(),stash_del.end(),cur_del_token) !=stash_del.end()){
                counter++;
            }

    }
    //printf("The counter %llu", counter);

}


void ecall_reset(){
    //reset the simulation
    stash_del.clear();
    w_del_tokens.clear();
}


