# Introduction

We design and implement forward and Type-I backward-private SE scheme, named Maiden. Our idea is straightforward yet practical. We keep the states of updates, the deletion information, and a sketch of insertions inside SGX Enclave so as to eliminate the leakage in updates and allow minimally necessary leakage during the search.

We compare Maiden with two other baseline schemes. First one is the simulation of Fort's enclave [2] and a ported version of Orion[3], (namedly Orion*) to SGX Enclave.

We also design and implement two forward and Type-II backward private SE schemes, named SGX-SE1 and SGX-SE2 [1]. By using SGX, the  communication cost between the client and server of achieving forward and backward privacy in SE is significantly reduced. 

We also attach datasets of streaming_enron.zip and streaming_syn_10_6.zip for testing purpose.

Both SGX-SE1 and SGX-SE2 leverage the SGX enclave to carefully track keyword states and document deletions, in order to minimise the communication overhead between the SGX and untrusted memory. In particular, SGX-SE2 is an optimised version of SGX-SE1 by employing Bloom filter to compress the states of database entries, which speeds up the search operations and  boosts the capacity of batch processing in addition and deletion. 

We also implement another SGX-based SE scheme Bunker-B [2] as the baseline of our evaluation to demonstrate the advantages of our schemes in runtime and storage costs.

We also add a sample STREAMING.ZIP dataset in every project for your testing.
Please unzip it before the execution.

# SE_SGX_1 Execution

1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:

   Using Hardware Mode and Debug build:
   
       `` $ cd SGX_SE1 && make clean``
       
       `` $ make SGX_MODE=HW SGX_DEBUG=1``

3. Execute the binary directly:
  `
    $ ./cryptoTestingApp
  `

4. This version is tested on Ubuntu 16.04/18.04 with SGX >=2.0

# SE_SGX_2 Execution

1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:

   Using Hardware Mode and Debug build:
   
      `` $ cd SGX_SE2 && make clean``
      
      `` $ make SGX_MODE=HW SGX_DEBUG=1``

3. Execute the binary directly:
  `
    $ ./cryptoTestingApp
  `

4. This version is tested on Ubuntu 16.04/18.04 with SGX >=2.0

# Bunker-B Execution

1. Install Intel(R) SGX SDK for Linux* OS

2. Build the project with the prepared Makefile:

   Using Hardware Mode and Debug build:
   
      ``$ cd Bunker-B && make clean``
      
      ``$ make SGX_MODE=HW SGX_DEBUG=1``

3. Execute the binary directly:
   `
     $ ./cryptoTestingApp
   `

4. This version is tested on Ubuntu 16.04/18.04 with SGX >=2.0


# Feedback
Email the authors: viet.vo@monash.edu, shangqi.lai@monash.edu, xingliang.yuan@monash.edu

# Reference
[1] Viet Vo, Shangqi Lai, Xingliang Yuan, Shi-Feng Sun, Surya Nepal, and Joseph K. Liu. 2020. Accelerating Forward and Backward Private Searchable Encryption Using Trusted Execution. In the 18th International Conference on Applied Cryptography and Network Security (ACNS), 2020. (Acceptance ratio: 21%)

[2] Ghous *Amjad*, Seny *Kamara*, and Tarik Moataz. 2019. Forward and Backward Private Searchable Encryption with SGX. In the 12th European Workshop on Systems Security (EuroSec), 2019.

[3] Javad Ghareh Chamani, Dimitrios Papadopoulos, Charalampos Papamanthou,and Rasool Jalili. 2018. New Constructions for Forward and Backward Private Symmetric Searchable Encryption. In ACM CCS 2018.
