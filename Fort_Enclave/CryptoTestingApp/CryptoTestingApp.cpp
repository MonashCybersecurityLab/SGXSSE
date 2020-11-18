
#include <string>
#include "stdio.h"
#include "stdlib.h"

#include "sgx_urts.h"
#include "CryptoEnclave_u.h"

#include "../common/data_type.h"

#include <inttypes.h>

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


void ocall_print_string(const char *str) {
    printf("%s\n", str);
}


//main func
int main()
{
	/* Setup enclave */
	sgx_enclave_id_t eid;
	sgx_status_t ret;
	sgx_launch_token_t token = { 0 };
	int token_updated = 0;
	
	printf("\Initiate enclave\n");

	ret = sgx_create_enclave(ENCLAVE_FILE, SGX_DEBUG_FLAG, &token, &token_updated, &eid, NULL);
	if (ret != SGX_SUCCESS)
	{
		printf("sgx_create_enclave failed: %#x\n", ret);
		return 1;
	}

//dev to simulate a combination of delete, and run

	//Enclave
	printf("\nSimulate enclave\n");

	//const unsigned int stash_del_size [] = {2316636};
	//const unsigned int w_delete_token_size [] = {35298,35027,29456,29063,28595,28206,27361,27082,22667,22407};

	const unsigned int stash_del_size [] = {6395329};
	const unsigned int w_delete_token_size [] = {1000000,563907,557167,519574,386098,359376,248601,194981,153253,137948};


	for (int i=0; i < 1; i++){
		for(int j=0; j < 10; j++){
			printf("\nSimulate (%d,%d)\n", stash_del_size[i],w_delete_token_size[j]);
			
			ecall_init(eid,stash_del_size[i],w_delete_token_size[j]);
			
			std::cout << timeSinceEpochMillisec() << std::endl;
			ecall_scan(eid);
			std::cout << timeSinceEpochMillisec() << std::endl;

			ecall_reset(eid);

			printf("\n--------\n");
		}

		printf("\nRunning new stash del size\n");
	}
	
	printf("\nFinish scanning\n");

	//destroy enclave
	ret = SGX_SUCCESS;
	ret = sgx_destroy_enclave(eid);
	if (ret != SGX_SUCCESS)
	{
		printf("App: error %#x, failed to destroy enclave .\n", ret);
	}


	return 0;
}

