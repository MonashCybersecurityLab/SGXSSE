#include "CryptoEnclave_t.h"

#include "EnclaveUtils.h"

#include "sgx_trts.h"
#include "sgx_tcrypto.h"
#include "stdlib.h"
#include <stdarg.h>
#include <stdio.h>
#include <string>
#include <unordered_map>
#include <iterator>
#include <vector>
#include <set>
#include "../common/data_type.h"

///// local variables inside Enclave
unsigned char KW[ENC_KEY_SIZE] = {0};
unsigned char KI[ENC_KEY_SIZE] = {0};

/*** setup */
void ecall_init(unsigned char *K1, size_t K1_len, unsigned char *K2, size_t K2_len){
    memcpy(KW, K1, K1_len);
    memcpy(KI, K2, K2_len);
}

void ecall_query_keyword(const char *keyword, size_t w_len, int *version, size_t v_len, int *count, size_t c_len) {
	/*** test segment */
	//ocall_print_string(keyword);
	//ocall_print_string(std::to_string(*version).c_str());
	//ocall_print_string(std::to_string(*count).c_str());

	int batch = *count / BATCH_SIZE;

	rand_t *qk1 = (rand_t*) malloc(BATCH_SIZE * sizeof(rand_t));
	rand_t *query = (rand_t*) malloc(BATCH_SIZE * sizeof(rand_t));
	rand_t *del = (rand_t*) malloc(BATCH_SIZE * sizeof(rand_t));
	std::string qk0 = std::string(keyword, w_len) + std::to_string(*version);

	// final result size
	long query_len = 0;
	long del_len = 0;

	// array for the query result
	std::string query_vec[250000];
	std::string del_vec[187500];

	// do batch process
	for(int i = 0; i <= batch; i++) {
		long query_res_batch = 0;
		long del_res_batch = 0;

		// determine the largest sequence no. in the current batch
		int limit = BATCH_SIZE * (i + 1) > *count ? *count : BATCH_SIZE * (i + 1);

		// determine the # of tokens in the current batch
		int length = BATCH_SIZE * (i + 1) > *count ? *count - BATCH_SIZE * i : BATCH_SIZE;
		
		for(int j = BATCH_SIZE * i + 1; j <= limit; j++) {
			std::string tki = qk0 + std::to_string(j);
			prf_F_improve(KW, tki.c_str(), tki.length() + 1, &qk1[j - BATCH_SIZE * i - 1]);
		}
		// ocall here to get result
		ocall_get_docId(qk1, query, length, sizeof(rand_t), &query_res_batch, sizeof(long));

		// ocall here to get deletion
		ocall_get_delId(qk1, del, length, sizeof(rand_t), &del_res_batch, sizeof(long));
		
		// decrypt doc Id and add it to the res array
		for(int i = 0; i < query_res_batch; i++) {
			rand_t temp;
			prf_Dec_improve(KI, query[i].content, query[i].content_length, &temp);
			query_vec[query_len + i] = std::string((char *) temp.content, temp.content_length);
		}
		query_len += query_res_batch;

		// decrypt deleted Id and add it to the del array
		for(int i = 0; i < del_res_batch; i++) {
			rand_t temp;
			prf_Dec_improve(KI, del[i].content, del[i].content_length, &temp);
			del_vec[del_len + i] = std::string((char *) temp.content, temp.content_length);
		}
		del_len += del_res_batch;
	}

	free(qk1);
	free(query);
	free(del);

	// merge results from D and d
	std::vector<std::string> res_set;

	/*for(int i = 0; i < query_len; i++) {
		bool add_flag = true;
		for(int j = 0; j < del_len; j++) {
			if(query_vec[i].content_length == del_vec[j].content_length) {
				if(!memcmp(query_vec[i].content, del_vec[j].content, query_vec[i].content_length)) {
					add_flag = false;
					break;
				}
			}
		}
		if(add_flag) {
			res_vec.push_back(query_vec[i]);
		}
	}*/
	std::set_difference(query_vec, query_vec + query_len,
			del_vec, del_vec + del_len,
			std::back_inserter(res_set));

	rand_t* res_vec = (rand_t *) malloc(res_set.size() * sizeof(rand_t));

	for(int i = 0; i < res_set.size(); i++) {
		res_vec[i].content_length = res_set[i].size();
		memcpy(res_vec[i].content, (unsigned char *) res_set[i].c_str(), res_set[i].size());
	}

	// release deletion vector
	//free(del_vec);
	// ocall here to send results back to the client
	
	ocall_send_to_client(res_vec, res_set.size(), sizeof(rand_t));
	
	free(res_vec);

	// re-encryption
	rand_t *v1 = (rand_t*) malloc(BATCH_SIZE * sizeof(rand_t));
	rand_t *v2 = (rand_t*) malloc(BATCH_SIZE * sizeof(rand_t));

	batch = res_set.size() / BATCH_SIZE;

	*count = 1;
	(*version)++;
	for(int i = 0; i <= batch; i++) {
		// determine the largest sequence no. in the current batch
		int limit = BATCH_SIZE * (i + 1) > res_set.size() ? res_set.size() : BATCH_SIZE * (i + 1);

		// determine the # of tokens in the current batch
		int length = BATCH_SIZE * (i + 1) > res_set.size() ? res_set.size() - BATCH_SIZE * i : BATCH_SIZE;
		
		for(int j = BATCH_SIZE * i; j < limit; j++) {
			std::string new_label = std::string(keyword, w_len) + std::to_string(*version) + std::to_string(*count);
			// compute new key and value
			prf_F_improve(KW, new_label.c_str(), new_label.length() + 1, &v1[j - BATCH_SIZE * i]);
			prf_Enc_improve(KI, res_set[j].c_str(), res_set[j].size(), &v2[j - BATCH_SIZE * i]);
			(*count)++;
		}

		// ocall here to update D
		ocall_transfer_updated_entries(v1, v2, length, sizeof(rand_t), &ADD, sizeof(int));
	}
	
	// release result vector
	free(v1);
	free(v2);
}

void ecall_update_doc(const char *keyword, size_t w_len, int *version, size_t v_len, int *count, size_t c_len, const char *doc_id, size_t id_len, const int* op, size_t op_len) {
	rand_t v1;
	rand_t v2;
	std::string new_label = std::string(keyword, w_len) + std::to_string(*version) + std::to_string(*count);
	// compute key and value
	prf_F_improve(KW, new_label.c_str(), new_label.length() + 1, &v1);
	prf_Enc_improve(KI, doc_id, id_len, &v2);
	// ocall here to update D
	ocall_transfer_updated_entries(&v1, &v2, 1, sizeof(rand_t), op, sizeof(int));
}

//
//void ecall_enc_aes_gcm(unsigned char *plaintext, size_t plaintext_len, unsigned char *ciphertext, size_t ciphertext_len)
//{
//  enc_aes_gcm(KF,plaintext,plaintext_len,ciphertext,ciphertext_len);
//}


//void ecall_dec_aes_gcm(unsigned char *ciphertext, size_t ciphertext_len, unsigned char *plaintext, size_t plaintext_len)
//{
//  dec_aes_gcm(KI,ciphertext,ciphertext_len,
//            plaintext,plaintext_len);
//}

