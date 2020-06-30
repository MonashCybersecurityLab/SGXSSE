# SE_SGX_1

We also add a sample STREAMING.ZIP dataset in every project for your testing.
Please unzip it before the execution.

You may want to test different following total number of supporting file and deletion proportion in CryptoTestingApp/CryptoTestingApp.cpp.

For example:

int total_file_no = (int)200000;//50000;//100000

int del_no = (int) 20000;//10000;

## How to Build/Execute the Application 
1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:

   Using Hardware Mode and Debug build:
   
       `` $ cd SE_SGX_1 && make clean``
       
       `` $ make SGX_MODE=HW SGX_DEBUG=1``

3. Execute the binary directly:
  `
    $ ./cryptoTestingApp
  `

## Worklog after Fork:
Mon 4 Mar, 19
- This version is only tested on Ubuntu 16.04/18.04 with SGX >=2.0
