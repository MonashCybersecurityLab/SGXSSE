#include "Client.h"

#include <string>
//#include <string.h> // memset(KF, 0, sizeof(KF));
#include "stdio.h"
#include <stdlib.h>
#include <fstream>
#include <iostream>
#include <sstream> //std::stringstream
#include <vector>
#include <algorithm> // for std::find
#include <iterator> // for std::begin, std::end
#include <cstring> 
#include <openssl/rand.h>


Client::Client(){
    file_reading_counter=0;
    RAND_bytes(KF,ENC_KEY_SIZE);
}

void Client::getKFValue(unsigned char * outKey){
    memcpy(outKey,KF,ENC_KEY_SIZE);
}

void Client::ReadNextDoc(docContent *content){
    std::ifstream inFile;
    std::stringstream strStream;
    //docContent content;

    //increase counter
    file_reading_counter+=1;

    std::string fileName;
    fileName = std::to_string(file_reading_counter);
    /** convert fileId to char* and record length */
    int doc_id_size = fileName.length() +1;
    
    content->id.doc_id = (char*) malloc(doc_id_size);
    memcpy(content->id.doc_id, fileName.c_str(),doc_id_size);
    content->id.id_length = doc_id_size;

    //read the file content
    inFile.open( raw_doc_dir + fileName); 
    strStream << inFile.rdbuf();
    inFile.close();

    /** convert document content to char* and record length */
    std::string str = strStream.str();
    int plaintext_len;
    plaintext_len = str.length()+1;

    content->content = (char*)malloc(plaintext_len);
    memcpy(content->content, str.c_str(),plaintext_len);

    content->content_length = plaintext_len;

    strStream.clear();

}

void Client::Del_GivenDocIndex(const int del_index, docId* delV_i){
    
    std::string fileName;
    fileName = std::to_string(del_index);

    delV_i->id_length = fileName.length() +1;
    delV_i->doc_id = (char*)malloc(delV_i->id_length);
    memcpy(delV_i->doc_id,fileName.c_str(),delV_i->id_length);

}

void Client::Del_GivenDocArray(const int * del_arr, docId* delV, int n){

    std::string fileName;
    for(int i = 0; i <n; i++){
        fileName = std::to_string(del_arr[i]);

        /** convert fileId to char* and record length */
        delV[i].id_length = fileName.length() +1;

        delV[i].doc_id = (char*)malloc(delV[i].id_length);
        memcpy(delV[i].doc_id,fileName.c_str(),delV[i].id_length);
    }
}

void Client::EncryptDoc(const docContent* data, entry *encrypted_doc ){

    memcpy(encrypted_doc->first.content,data->id.doc_id,data->id.id_length);
	encrypted_doc->second.message_length = enc_aes_gcm((unsigned char*)data->content,
                                                        data->content_length,KF,
                                                        (unsigned char*)encrypted_doc->second.message);
}


void Client::DecryptDocCollection(std::vector<std::string> Res){
    
    for(auto&& enc_doc: Res){

        int original_len;
	    unsigned char *plaintext =(unsigned char*)malloc((enc_doc.size() - AESGCM_MAC_SIZE - AESGCM_IV_SIZE)*sizeof(unsigned char));
	    original_len= dec_aes_gcm((unsigned char*)enc_doc.c_str(),enc_doc.size(),KF,plaintext);
      
        //std::string doc_i((char*)plaintext,original_len);
        //printf("Plain doc ==> %s\n",doc_i.c_str());
    
    }
}
