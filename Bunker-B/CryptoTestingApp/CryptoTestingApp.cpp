
#include <string>
#include "stdio.h"
#include "stdlib.h"

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"
#include "../common/data_type.h"

#include <iostream>
#include "Server.h"
#include "Client.h"
#include "Utils.h"

//for measurement
#include <cstdint>
#include <chrono>
#include <iostream>
uint64_t timeSinceEpochMillisec() {
  using namespace std::chrono;
  return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}
//end for measurement

using std::cout;
using std::endl;
using std::pair;

#define ENCLAVE_FILE "CryptoEnclave.signed.so"

int total_file_no = (int)200000;//50000;//100000
int del_no = (int) 20000;//10000;

Client* myClient = new Client();
Server* myServer = new Server();

void ocall_print_string(const char *str) {
    printf("%s\n", str);
}

void ocall_print_int(size_t *str) {
    printf("%ld\n", *str);
}

void ocall_get_docId(void* token_list, void* res_list, size_t token_size, size_t cipher_length, long *res, size_t res_len) {
	// query D in the untrusted server
	std::vector<std::string> query_result = myServer->QueryToken((rand_t *) token_list, token_size);
	*res = query_result.size();
	//printf("%ld documents found\n", *res);

	// fill the output array
	for(int i = 0; i < query_result.size(); i++) {
		memcpy(((rand_t *) res_list + i)->content, query_result[i].c_str(), query_result[i].length());
		((rand_t *) res_list + i)->content_length = query_result[i].length();
	}
}

void ocall_get_delId(void* token_list, void* del_list, size_t token_size, size_t cipher_length, long *del, size_t del_len) {
	// query D in the untrusted server
	std::vector<std::string> deletion_result = myServer->QueryDeletion((rand_t *) token_list, token_size);
	*del = deletion_result.size();
	//printf("%ld documents deleted\n", *del);

	// fill the output array
	for(int i = 0; i < deletion_result.size(); i++) {
		memcpy(((rand_t *) del_list + i)->content, deletion_result[i].c_str(), deletion_result[i].length());
		((rand_t *) del_list + i)->content_length = deletion_result[i].length();
	}
}

void ocall_send_to_client(void* res_list, size_t res_size, size_t cipher_length) {
	myClient->ReceiveResult((rand_t *) res_list, res_size);
}

void ocall_transfer_updated_entries(void *v1, void *v2, size_t utoken_size, size_t cipher_length, const int* op, size_t op_len) {
	// add all entries into D
	//printf("%ld\n", utoken_size);
	myServer->ReceiveUpdate((rand_t *) v1, (rand_t *) v2, utoken_size, *op);
}

int main()
{
	/* Setup enclave */
	sgx_enclave_id_t eid;
	sgx_status_t ret;
	sgx_launch_token_t token = { 0 };
	int token_updated = 0;
	
	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("sgx_create_enclave failed: %#x\n", ret);
		return 1;
	}

	/* Setup Protocol*/
	//enclave
	unsigned char KWvalue[ENC_KEY_SIZE];
    unsigned char KIvalue[ENC_KEY_SIZE];
	myClient->getKWValue(KWvalue);
    myClient->getKIValue(KIvalue);
	ecall_init(eid, KWvalue, (size_t) ENC_KEY_SIZE, KIvalue, (size_t) ENC_KEY_SIZE);

	/*** Update Protocol with op = add */
	printf("Adding doc\n");
	/*** Update Protocol with op = add */
	for(int i=1;i <= total_file_no; i++){ //5
		//client read a document
		//printf("->%d",i);
		docContent fetch_data = myClient->ReadNextDoc();

		//encrypt and send to Server
		entry encrypted_entry = myClient->EncryptDoc(fetch_data);
		myServer->ReceiveEncDoc(encrypted_entry);

		//upload (op,in) to Enclave
		myClient->UpdateIndex(eid, fetch_data, ADD);

	}

	/*** Search keyword */
	/*
	std::cout << "Searching: " << keyword << endl;
	std::cout << timeSinceEpochMillisec() << std::endl;
	myClient->Search(eid, keyword);
	std::cout << timeSinceEpochMillisec() << std::endl;
	std::cout << "Searching: " << keyword << " after D re-encrypted" << endl;
	myClient->Search(eid, keyword);
	 */

	/*** Update an entry (Add new doc) */
	/*
	docContent fetch_data = myClient->ReadNextDoc();
	entry encrypted_entry = myClient->EncryptDoc(fetch_data);
	myServer->ReceiveEncDoc(encrypted_entry);
	myClient->UpdateIndex(eid, fetch_data, ADD);

	** Search keyword After Insertion
	std::cout << "Searching: " << keyword << " after D updated (Add)" << endl;
	myClient->Search(eid, keyword);*/

	/*** Update Protocol with op = del (id) */
	printf("\nDeleting doc\n");
	docContent content;
	for(int del_index=1; del_index <=del_no; del_index++){
		myClient->Del_GivenDocIndex(del_index, &content);
		//printf("->%s",content.id.doc_id);
		myClient->UpdateIndex(eid, content, DEL);
	}
	//std::vector<docContent> delV = myClient->Del_GivenDocArray(deleted_arr, 1000);
	//for(auto&& delDoc: delV){
	//	printf("->%s",delDoc.id.doc_id);
	//	myClient->UpdateIndex(eid, delDoc, DEL);
	//}

	/*** Update an entry (Del doc) */
	//myClient->UpdateIndex(eid, fetch_data, DEL);

	/*** Search keyword after Deletion */
	//std::cout << "\nSearching: " << keyword << endl;
	
	std::string s_keyword[50]= {"the", "of", "and", "to", "a", "in", "for", "is", "on", "that",
		"by", "this", "with", "i", "you", "it", "not", "or", "be", "are",
		"from", "at", "as", "your", "all", "have", "new", "more", "an", "was",
		"we", "will", "home", "can", "us", "about", "if", "page", "my", "has",
		"search", "free", "but", "our", "one", "other", "do", "no", "information", "time"};

	std::cout << timeSinceEpochMillisec() << std::endl;
	for (int s_i = 0; s_i < 50; s_i++){
		printf("\nSearching ==> %s\n", s_keyword[s_i].c_str());		
		myClient->Search(eid, s_keyword[s_i], myServer);
		printf("\n");
			
	}
	std::cout << timeSinceEpochMillisec() << std::endl;
	
	/*** Search keyword after empty the deleted entries */
	//std::cout << "Searching: " << keyword << " after empty d" << endl;
	//myClient->Search(eid, keyword);

	delete myClient;
	delete myServer;

	return 0;
}

