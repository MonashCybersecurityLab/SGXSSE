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

#include "../common/data_type.h"
#include "Utils.h"
#include <vector>

class Client{
    public:
        Client();
        void ReadNextDoc(docContent *fetch_data);
        void Del_GivenDocIndex(const int del_index, docId* delV_i);
        void Del_GivenDocArray(const int * del_arr, docId* delV, int n);
        void getKFValue(unsigned char * outKey);
        void EncryptDoc(const docContent *data, entry *encrypted_doc );
        void DecryptDocCollection(std::vector<std::string> Res);

    private:
        unsigned char KF[ENC_KEY_SIZE];
        int file_reading_counter;
};
 
#endif