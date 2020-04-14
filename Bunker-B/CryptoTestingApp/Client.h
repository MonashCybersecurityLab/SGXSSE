/***
 * Demonstrate Client
 * maintain a current Kf
 * read documents in a given directory and give one by one to App.cpp with <fileId, array of words>
 * develop utility to enc and dec file with a given key kf
 * issue a random update operation (op,in) to App
 * issue a random keyword search
 */
#ifndef CLIENT_H
#define CLIENT_H

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "../common/data_type.h"
#include "Utils.h"
#include "Server.h"

class Client{
    public:
        Client();
        docContent ReadNextDoc();
        void Search(sgx_enclave_id_t eid, std::string keyword, Server* server); //for search
        void UpdateIndex(sgx_enclave_id_t eid, docContent data, const int op);
        void ReceiveResult(rand_t* res_list, size_t res_size);
        void getKWValue(unsigned char * outKey);
        void getKIValue(unsigned char * outKey);
        std::vector<std::string> getQueryId();
        entry EncryptDoc(docContent data);
        void UpdateST(std::vector<std::string> word_list);
        void Del_GivenDocIndex(int index, docContent *content);

    private:
        std::unordered_map<std::string, entryState> ST;
        std::vector<std::string> query_result;
        unsigned char KW[ENC_KEY_SIZE];
        unsigned char KI[ENC_KEY_SIZE];
        unsigned char KF[ENC_KEY_SIZE];
        int file_reading_counter;
};
 
#endif
