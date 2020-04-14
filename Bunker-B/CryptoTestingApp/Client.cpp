#include "Client.h"

#include <string>
//#include <string.h> // memset(KF, 0, sizeof(KF));
#include "stdio.h"
#include <fstream>
#include <iostream>
#include <sstream> //std::stringstream
#include <vector>
#include <cstring> 
#include <openssl/rand.h>


Client::Client(){
    file_reading_counter = 0;
    RAND_bytes(KW, ENC_KEY_SIZE);
    RAND_bytes(KI, ENC_KEY_SIZE);
    RAND_bytes(KF, ENC_KEY_SIZE);
}

void Client::getKWValue(unsigned char * outKey){
    memcpy(outKey, KW, ENC_KEY_SIZE);
}

void Client::getKIValue(unsigned char * outKey){
    memcpy(outKey, KI, ENC_KEY_SIZE);
}

std::vector<std::string> Client::getQueryId() {
	return query_result;
}

void Client::Search(sgx_enclave_id_t eid, std::string keyword, Server* server){
	if(ST.find(keyword) == ST.end()) {	// invalid keyword
		return;
	} else {
		// call to Enclave
		ecall_query_keyword(eid, keyword.c_str(), keyword.size()
				, &ST[keyword].version, sizeof(int)
				, &ST[keyword].count, sizeof(int));

		// update version
		ST[keyword].version++;

		if(query_result.size() > 0) {
			for(std::string id : query_result) {
				std::string enc_doc = server->RetrieveDoc(id);
				unsigned char content[enc_doc.size()];
				dec_aes_gcm((unsigned char *) enc_doc.c_str(), enc_doc.size(), KF, content);
				//std::cout << content << std::endl;
			}
		}
	}
}

void Client::UpdateIndex(sgx_enclave_id_t eid, docContent data, const int op) {
	//parse content to keywords splited by comma
	std::vector<std::string> word_list;
	word_list = wordTokenize(data.content, data.content_length);

	// add to ST
	this->UpdateST(word_list);

	// send keyword/id to enclave
	for(int i = 0; i < word_list.size(); i++) {
		ecall_update_doc(eid, word_list[i].c_str(), word_list[i].size()
				, &ST[word_list[i]].version, sizeof(int)
				, &ST[word_list[i]].count, sizeof(int)
				, data.id.doc_id, data.id.id_length
				, &op, sizeof(int));
	}
}
void Client::ReceiveResult(rand_t* res_list, size_t res_size) {
	query_result.clear();
	//std::cout << "Query Result: ";
	for(int i = 0; i < res_size; i++) {
		query_result.push_back(std::string((char *) res_list[i].content, res_list[i].content_length));
		//std::cout << res_list[i].content << " ";
	}
	//std::cout << query_result.size() <<std::endl;
}

docContent Client::ReadNextDoc(){
    std::ifstream inFile;
    std::stringstream strStream;
    docContent content;
    docId id;

    //increase counter
    file_reading_counter += 1;

    std::string fileName;
    fileName = std::to_string(file_reading_counter);
    /** convert fileId to char* and record length */
    int doc_id_size = fileName.length();
    char *doc_id = new char[doc_id_size]; 
    std::strcpy(doc_id, fileName.c_str());
    id.id_length = doc_id_size;
    id.doc_id = doc_id;

    //read the file content
    inFile.open(raw_doc_dir + fileName);
    strStream << inFile.rdbuf();
    inFile.close();
    /** convert document content to char* and record length */
    std::string str = strStream.str();
    int plaintext_len;
    plaintext_len = str.length() + 1;
    char * cstr = new  char[plaintext_len];
    std::strcpy(cstr, str.c_str());

    content.id = id;
    content.content = cstr;
    content.content_length = plaintext_len;

    strStream.clear();

    return content;
}


entry Client::EncryptDoc(docContent data){

    entry encrypted_doc;
    //print original content
    //printf("Original\n");
    //print_bytes((uint8_t*)data.content,(uint32_t)data.content_length);

    encrypted_doc.first.content = (unsigned char *) data.id.doc_id;
    encrypted_doc.first.content_length = data.id.id_length;

    unsigned char *ciphertext;
	int cipher_len;
    ciphertext = (unsigned char *) malloc(data.content_length + AESGCM_MAC_SIZE + AESGCM_IV_SIZE);
	cipher_len = enc_aes_gcm((unsigned char*) data.content, data.content_length, KF, ciphertext);

    encrypted_doc.second.message = (char*) ciphertext;
    encrypted_doc.second.message_length = (size_t) cipher_len;

	return encrypted_doc;
}

void Client::UpdateST(std::vector<std::string> word_list) {
	/*** Add keyword into SR */
	// add new keyword
	for(int i = 0; i < word_list.size(); i++) {
		// set init state if the keyword does not exist before
	    if(ST.find(word_list[i]) == ST.end()) {
	    	entryState state;
	        state.count = 1;
	        state.version = 0;
	        ST[word_list[i]] = state;
	    }
	    else {
	    	ST[word_list[i]].count++;
	    }
	}
}

void Client::Del_GivenDocIndex(int index, docContent *content) {
	std::ifstream inFile;
	std::stringstream strStream;
	docId id;


	std::string fileName;
	fileName = std::to_string(index);
	/** convert fileId to char* and record length */
	int doc_id_size = fileName.length();
	char *doc_id = new char[doc_id_size];
	std::strcpy(doc_id, fileName.c_str());
	id.id_length = doc_id_size;
	id.doc_id = doc_id;

	//read the file content
	inFile.open(raw_doc_dir + fileName);
	strStream << inFile.rdbuf();
	inFile.close();
	/** convert document content to char* and record length */
	std::string str = strStream.str();
	int plaintext_len;
	plaintext_len = str.length() + 1;
	char * cstr = new  char[plaintext_len];
	std::strcpy(cstr, str.c_str());

	content->id = id;
	content->content = cstr;
	content->content_length = plaintext_len;

	strStream.clear();
}


