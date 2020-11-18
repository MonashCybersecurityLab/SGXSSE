#ifndef CRYPTOENCLAVE_U_H__
#define CRYPTOENCLAVE_U_H__

#include <stdint.h>
#include <wchar.h>
#include <stddef.h>
#include <string.h>
#include "sgx_edger8r.h" /* for sgx_status_t etc. */


#include <stdlib.h> /* for size_t */

#define SGX_CAST(type, item) ((type)(item))

#ifdef __cplusplus
extern "C" {
#endif

#ifndef OCALL_PRINT_STRING_DEFINED__
#define OCALL_PRINT_STRING_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_print_string, (const char* str));
#endif
#ifndef OCALL_TRANSFER_ENCRYPTED_ENTRIES_DEFINED__
#define OCALL_TRANSFER_ENCRYPTED_ENTRIES_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_transfer_encrypted_entries, (const void* t1_u_arr, const void* t1_v_arr, int pair_count, int rand_size));
#endif
#ifndef OCALL_RETRIEVE_ENCRYPTED_DOC_DEFINED__
#define OCALL_RETRIEVE_ENCRYPTED_DOC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_retrieve_encrypted_doc, (const char* del_id, size_t del_id_len, unsigned char* encrypted_content, size_t maxLen, int* length_content, size_t int_len));
#endif
#ifndef OCALL_DEL_ENCRYPTED_DOC_DEFINED__
#define OCALL_DEL_ENCRYPTED_DOC_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_del_encrypted_doc, (const char* del_id, size_t del_id_len));
#endif
#ifndef OCALL_QUERY_TOKENS_ENTRIES_DEFINED__
#define OCALL_QUERY_TOKENS_ENTRIES_DEFINED__
void SGX_UBRIDGE(SGX_NOCONVENTION, ocall_query_tokens_entries, (const void* Q_w_u_arr, const void* Q_w_id_arr, int pair_count, int rand_size));
#endif
#ifndef SGX_OC_CPUIDEX_DEFINED__
#define SGX_OC_CPUIDEX_DEFINED__
void SGX_UBRIDGE(SGX_CDECL, sgx_oc_cpuidex, (int cpuinfo[4], int leaf, int subleaf));
#endif
#ifndef SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_WAIT_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_wait_untrusted_event_ocall, (const void* self));
#endif
#ifndef SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
#define SGX_THREAD_SET_UNTRUSTED_EVENT_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_untrusted_event_ocall, (const void* waiter));
#endif
#ifndef SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SETWAIT_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_setwait_untrusted_events_ocall, (const void* waiter, const void* self));
#endif
#ifndef SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
#define SGX_THREAD_SET_MULTIPLE_UNTRUSTED_EVENTS_OCALL_DEFINED__
int SGX_UBRIDGE(SGX_CDECL, sgx_thread_set_multiple_untrusted_events_ocall, (const void** waiters, size_t total));
#endif

sgx_status_t ecall_init(sgx_enclave_id_t eid, unsigned char* keyF, size_t len);
sgx_status_t ecall_addDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length, char* content, int content_length);
sgx_status_t ecall_delDoc(sgx_enclave_id_t eid, char* doc_id, size_t id_length);
sgx_status_t ecall_search(sgx_enclave_id_t eid, const char* keyword, size_t len);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif
