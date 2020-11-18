
#include <string>
#include "stdio.h"
#include "stdlib.h"

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "../common/data_type.h"
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


#define ENCLAVE_FILE "CryptoEnclave.signed.so"

int total_file_no = (int)85000;
int del_no = (int)21250;


Client *myClient; //extern to separate ocall
Server *myServer; //extern to separate ocall

void ocall_print_string(const char *str) {
    printf("%s\n", str);
}

void ocall_transfer_encrypted_entries(const void *_t1_u_arr,
									  const void *_t1_v_arr, 
									  int pair_count, int rand_size){

	myServer->ReceiveTransactions(
								(rand_t *)_t1_u_arr,(rand_t *)_t1_v_arr,
								pair_count);

}

void ocall_retrieve_encrypted_doc(const char *del_id, size_t del_id_len, 
                                  unsigned char *encrypted_content, size_t maxLen,
                                  int *length_content, size_t int_size){
								  
	std::string del_id_str(del_id,del_id_len);	
	std::string encrypted_entry = myServer->Retrieve_Encrypted_Doc(del_id_str);
	
    *length_content = (int)encrypted_entry.size();

	//later double check *length_content exceeds maxLen
    memcpy(encrypted_content, (unsigned char*)encrypted_entry.c_str(),encrypted_entry.size());
}

void ocall_del_encrypted_doc(const char *del_id, size_t del_id_len){
	std::string del_id_str(del_id,del_id_len);
	myServer->Del_Encrypted_Doc(del_id_str);
}


void ocall_query_tokens_entries(const void *Q_w_u_arr,
                               const void *Q_w_id_arr,
                               int pair_count, int rand_size){
	
	std::vector<std::string> Res;
	Res = myServer->retrieve_query_results(
								(rand_t *)Q_w_u_arr,(rand_t *)Q_w_id_arr,
								pair_count);
	
	//give to Client for decryption
	myClient->DecryptDocCollection(Res);
}


//main func
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
	//Client
	myClient= new Client();

	//Enclave
	unsigned char KFvalue[ENC_KEY_SIZE];
	myClient->getKFValue(KFvalue);
	ecall_init(eid,KFvalue,(size_t)ENC_KEY_SIZE);

	//Server	
	myServer= new Server();

	unsigned long long start, end;
	printf("Adding doc\n");

	std::cout << timeSinceEpochMillisec() << std::endl;
	
	/*** Update Protocol with op = add */
	for(int i=1;i <= total_file_no; i++){  //total_file_no
		//client read a document
		//printf("->%d",i);
		
		docContent *fetch_data;
		fetch_data = (docContent *)malloc(sizeof( docContent));
		myClient->ReadNextDoc(fetch_data);

		//encrypt and send to Server
		entry *encrypted_entry;
		encrypted_entry = (entry*)malloc(sizeof(entry));
		
		encrypted_entry->first.content_length = fetch_data->id.id_length;
		encrypted_entry->first.content = (char*) malloc(fetch_data->id.id_length);
		encrypted_entry->second.message_length = fetch_data->content_length + AESGCM_MAC_SIZE + AESGCM_IV_SIZE;		
		encrypted_entry->second.message = (char *)malloc(encrypted_entry->second.message_length);


		myClient->EncryptDoc(fetch_data,encrypted_entry);
		
		myServer->ReceiveEncDoc(encrypted_entry);
		
		//upload (op,in) to Enclave
		ecall_addDoc(eid,fetch_data->id.doc_id,fetch_data->id.id_length,
						fetch_data->content,fetch_data->content_length);

		//free memory 
		free(fetch_data->content);
		free(fetch_data->id.doc_id);
		free(fetch_data);

		free(encrypted_entry->first.content);
		free(encrypted_entry->second.message);
		free(encrypted_entry);
	}

	std::cout << timeSinceEpochMillisec() << std::endl;
	
	//** Update Protocol with op = del (id)
	printf("\nDeleting doc\n");
	
	docId* delV = new docId[del_no];
	docId delV_i;


	std::cout << timeSinceEpochMillisec() << std::endl;
	for(int del_index=1; del_index <=del_no; del_index++){
//		//printf("->%s",delV_i[del_index].doc_id);
		myClient->Del_GivenDocIndex(del_index, &delV_i);
		ecall_delDoc(eid,delV_i.doc_id,delV_i.id_length);
	}

	free(delV_i.doc_id);

	std::cout << timeSinceEpochMillisec() << std::endl;


	//std::string s_keyword[10]={"the","of","and","to","a","in","for","is","on","that"};
	std::string s_keyword[10]={"pleas","the","cc","enron","PM","forward","thank","would","know","If"};

	for (int s_i = 0; s_i < 10; s_i++){
		printf("\nSearching ==> %s\n", s_keyword[s_i].c_str());

		std::cout << timeSinceEpochMillisec() << std::endl;
		ecall_search(eid, s_keyword[s_i].c_str(), s_keyword[s_i].size());
		std::cout << timeSinceEpochMillisec() << std::endl;
		//printf("\n-> %llu\n", start - end);
	}

	delete myClient;
	delete myServer;

	//destroy enclave
	ret = SGX_SUCCESS;
	ret = sgx_destroy_enclave(eid);
	if (ret != SGX_SUCCESS)
	{
		printf("App: error %#x, failed to destroy enclave .\n", ret);
	}

	return 0;
}

