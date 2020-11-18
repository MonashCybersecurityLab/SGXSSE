#include "CryptoEnclave_u.h"
#include <errno.h>

typedef struct ms_ecall_addDoc_t {
	char* ms_doc_id;
	size_t ms_id_length;
	unsigned int ms_docInt;
	char* ms_content;
	int ms_content_length;
} ms_ecall_addDoc_t;

typedef struct ms_ecall_delDoc_t {
	char* ms_doc_id;
	size_t ms_id_length;
	unsigned int ms_docInt;
	char* ms_content;
	int ms_content_length;
} ms_ecall_delDoc_t;

typedef struct ms_ecall_search_t {
	const char* ms_keyword;
	size_t ms_len;
} ms_ecall_search_t;

typedef struct ms_ocall_get_bucket_t {
	int ms_data_structure;
	size_t ms_index;
	unsigned char* ms_bucket;
	size_t ms_bucket_size;
} ms_ocall_get_bucket_t;

typedef struct ms_ocall_put_bucket_t {
	int ms_data_structure;
	size_t ms_index;
	const unsigned char* ms_bucket;
	size_t ms_bucket_size;
} ms_ocall_put_bucket_t;

typedef struct ms_ocall_print_string_t {
	const char* ms_str;
} ms_ocall_print_string_t;

typedef struct ms_ocall_transfer_encrypted_entries_t {
	const void* ms_t1_u_arr;
	const void* ms_t1_v_arr;
	int ms_pair_count;
	int ms_rand_size;
} ms_ocall_transfer_encrypted_entries_t;

typedef struct ms_ocall_retrieve_encrypted_doc_t {
	const char* ms_del_id;
	size_t ms_del_id_len;
	unsigned char* ms_encrypted_content;
	size_t ms_maxLen;
	int* ms_length_content;
	size_t ms_int_len;
} ms_ocall_retrieve_encrypted_doc_t;

typedef struct ms_ocall_del_encrypted_doc_t {
	const char* ms_del_id;
	size_t ms_del_id_len;
} ms_ocall_del_encrypted_doc_t;

typedef struct ms_ocall_retrieve_M_c_t {
	void* ms__u_prime;
	size_t ms__u_prime_size;
	void* ms__v_prime;
	size_t ms__v_prime_size;
	size_t ms_token_size;
	int* ms_v_size;
	size_t ms_int_len;
} ms_ocall_retrieve_M_c_t;

typedef struct ms_ocall_del_M_c_value_t {
	const unsigned char* ms__u_prime;
	size_t ms__u_prime_size;
} ms_ocall_del_M_c_value_t;

typedef struct ms_ocall_query_tokens_entries_t {
	const void* ms_Q_w_u_arr;
	const void* ms_Q_w_id_arr;
	int ms_pair_count;
	int ms_rand_size;
} ms_ocall_query_tokens_entries_t;

typedef struct ms_sgx_oc_cpuidex_t {
	int* ms_cpuinfo;
	int ms_leaf;
	int ms_subleaf;
} ms_sgx_oc_cpuidex_t;

typedef struct ms_sgx_thread_wait_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_self;
} ms_sgx_thread_wait_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_set_untrusted_event_ocall_t {
	int ms_retval;
	const void* ms_waiter;
} ms_sgx_thread_set_untrusted_event_ocall_t;

typedef struct ms_sgx_thread_setwait_untrusted_events_ocall_t {
	int ms_retval;
	const void* ms_waiter;
	const void* ms_self;
} ms_sgx_thread_setwait_untrusted_events_ocall_t;

typedef struct ms_sgx_thread_set_multiple_untrusted_events_ocall_t {
	int ms_retval;
	const void** ms_waiters;
	size_t ms_total;
} ms_sgx_thread_set_multiple_untrusted_events_ocall_t;

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_get_bucket(void* pms)
{
	ms_ocall_get_bucket_t* ms = SGX_CAST(ms_ocall_get_bucket_t*, pms);
	ocall_get_bucket(ms->ms_data_structure, ms->ms_index, ms->ms_bucket, ms->ms_bucket_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_put_bucket(void* pms)
{
	ms_ocall_put_bucket_t* ms = SGX_CAST(ms_ocall_put_bucket_t*, pms);
	ocall_put_bucket(ms->ms_data_structure, ms->ms_index, ms->ms_bucket, ms->ms_bucket_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_print_string(void* pms)
{
	ms_ocall_print_string_t* ms = SGX_CAST(ms_ocall_print_string_t*, pms);
	ocall_print_string(ms->ms_str);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_transfer_encrypted_entries(void* pms)
{
	ms_ocall_transfer_encrypted_entries_t* ms = SGX_CAST(ms_ocall_transfer_encrypted_entries_t*, pms);
	ocall_transfer_encrypted_entries(ms->ms_t1_u_arr, ms->ms_t1_v_arr, ms->ms_pair_count, ms->ms_rand_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_retrieve_encrypted_doc(void* pms)
{
	ms_ocall_retrieve_encrypted_doc_t* ms = SGX_CAST(ms_ocall_retrieve_encrypted_doc_t*, pms);
	ocall_retrieve_encrypted_doc(ms->ms_del_id, ms->ms_del_id_len, ms->ms_encrypted_content, ms->ms_maxLen, ms->ms_length_content, ms->ms_int_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_del_encrypted_doc(void* pms)
{
	ms_ocall_del_encrypted_doc_t* ms = SGX_CAST(ms_ocall_del_encrypted_doc_t*, pms);
	ocall_del_encrypted_doc(ms->ms_del_id, ms->ms_del_id_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_retrieve_M_c(void* pms)
{
	ms_ocall_retrieve_M_c_t* ms = SGX_CAST(ms_ocall_retrieve_M_c_t*, pms);
	ocall_retrieve_M_c(ms->ms__u_prime, ms->ms__u_prime_size, ms->ms__v_prime, ms->ms__v_prime_size, ms->ms_token_size, ms->ms_v_size, ms->ms_int_len);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_del_M_c_value(void* pms)
{
	ms_ocall_del_M_c_value_t* ms = SGX_CAST(ms_ocall_del_M_c_value_t*, pms);
	ocall_del_M_c_value(ms->ms__u_prime, ms->ms__u_prime_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_ocall_query_tokens_entries(void* pms)
{
	ms_ocall_query_tokens_entries_t* ms = SGX_CAST(ms_ocall_query_tokens_entries_t*, pms);
	ocall_query_tokens_entries(ms->ms_Q_w_u_arr, ms->ms_Q_w_id_arr, ms->ms_pair_count, ms->ms_rand_size);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_oc_cpuidex(void* pms)
{
	ms_sgx_oc_cpuidex_t* ms = SGX_CAST(ms_sgx_oc_cpuidex_t*, pms);
	sgx_oc_cpuidex(ms->ms_cpuinfo, ms->ms_leaf, ms->ms_subleaf);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_wait_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_wait_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_wait_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_wait_untrusted_event_ocall(ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_set_untrusted_event_ocall(void* pms)
{
	ms_sgx_thread_set_untrusted_event_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_untrusted_event_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_untrusted_event_ocall(ms->ms_waiter);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_setwait_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_setwait_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_setwait_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_setwait_untrusted_events_ocall(ms->ms_waiter, ms->ms_self);

	return SGX_SUCCESS;
}

static sgx_status_t SGX_CDECL CryptoEnclave_sgx_thread_set_multiple_untrusted_events_ocall(void* pms)
{
	ms_sgx_thread_set_multiple_untrusted_events_ocall_t* ms = SGX_CAST(ms_sgx_thread_set_multiple_untrusted_events_ocall_t*, pms);
	ms->ms_retval = sgx_thread_set_multiple_untrusted_events_ocall(ms->ms_waiters, ms->ms_total);

	return SGX_SUCCESS;
}

static const struct {
	size_t nr_ocall;
	void * table[14];
} ocall_table_CryptoEnclave = {
	14,
	{
		(void*)CryptoEnclave_ocall_get_bucket,
		(void*)CryptoEnclave_ocall_put_bucket,
		(void*)CryptoEnclave_ocall_print_string,
		(void*)CryptoEnclave_ocall_transfer_encrypted_entries,
		(void*)CryptoEnclave_ocall_retrieve_encrypted_doc,
		(void*)CryptoEnclave_ocall_del_encrypted_doc,
		(void*)CryptoEnclave_ocall_retrieve_M_c,
		(void*)CryptoEnclave_ocall_del_M_c_value,
		(void*)CryptoEnclave_ocall_query_tokens_entries,
		(void*)CryptoEnclave_sgx_oc_cpuidex,
		(void*)CryptoEnclave_sgx_thread_wait_untrusted_event_ocall,
		(void*)CryptoEnclave_sgx_thread_set_untrusted_event_ocall,
		(void*)CryptoEnclave_sgx_thread_setwait_untrusted_events_ocall,
		(void*)CryptoEnclave_sgx_thread_set_multiple_untrusted_events_ocall,
	}
};
sgx_status_t ecall_free(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 0, &ocall_table_CryptoEnclave, NULL);
	return status;
}

sgx_status_t ecall_flush(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 1, &ocall_table_CryptoEnclave, NULL);
	return status;
}

sgx_status_t ecall_init(sgx_enclave_id_t eid)
{
	sgx_status_t status;
	status = sgx_ecall(eid, 2, &ocall_table_CryptoEnclave, NULL);
	return status;
}

sgx_status_t ecall_addDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length, unsigned int docInt, char* content, int content_length)
{
	sgx_status_t status;
	ms_ecall_addDoc_t ms;
	ms.ms_doc_id = doc_id;
	ms.ms_id_length = id_length;
	ms.ms_docInt = docInt;
	ms.ms_content = content;
	ms.ms_content_length = content_length;
	status = sgx_ecall(eid, 3, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_delDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length, unsigned int docInt, char* content, int content_length)
{
	sgx_status_t status;
	ms_ecall_delDoc_t ms;
	ms.ms_doc_id = doc_id;
	ms.ms_id_length = id_length;
	ms.ms_docInt = docInt;
	ms.ms_content = content;
	ms.ms_content_length = content_length;
	status = sgx_ecall(eid, 4, &ocall_table_CryptoEnclave, &ms);
	return status;
}

sgx_status_t ecall_search(sgx_enclave_id_t eid, const char* keyword, size_t len)
{
	sgx_status_t status;
	ms_ecall_search_t ms;
	ms.ms_keyword = keyword;
	ms.ms_len = len;
	status = sgx_ecall(eid, 5, &ocall_table_CryptoEnclave, &ms);
	return status;
}

