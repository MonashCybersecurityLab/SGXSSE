# Introduction

We design and implement two forward and backward private SE schemes, named SGX-SE1 and SGX-SE2 [1]. By using SGX, the  communication cost between the client and server of achieving forward and backward privacy in SE is significantly reduced. 

Both SGX-SE1 and SGX-SE2 leverage the SGX enclave to carefully track keyword states and document deletions, in order to minimise the communication overhead between the SGX and untrusted memory. In particular, SGX-SE2 is an optimised version of SGX-SE1 by employing Bloom filter to compress the states of database entries, which speeds up the search operations and  boosts the capacity of batch processing in addition and deletion. 

We also implement another SGX-based SE scheme Bunker-B [2] as the baseline of our evaluation to demonstrate the advantages of our schemes in runtime and storage costs.

# SE_SGX_1 Execution

1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:

   Using Hardware Mode, Pre-release build:
       ``$ cd SGX_SE1 && make SGX_MODE=HW SGX_PRERELEASE=1``

3. Execute the binary directly:
  `
    $ ./_cryptoTestingApp
  `

4. This version is tested on Ubuntu 16.04/18.04 with SGX >=2.0

# SE_SGX_2 Execution

1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:

   Using Hardware Mode, Pre-release build:
      `` $ cd SGX_SE2 && make SGX_MODE=HW SGX_PRERELEASE=1``

3. Execute the binary directly:
  `
    $ ./_cryptoTestingApp
  `

4. This version is tested on Ubuntu 16.04/18.04 with SGX >=2.0

# Bunker-B Execution

1. Install Intel(R) SGX SDK for Linux* OS

2. Build the project with the prepared Makefile:

   Using Hardware Mode, Pre-release build:
      ``$ cd Bunker-B && make SGX_MODE=HW SGX_PRERELEASE=1``

3. Execute the binary directly:
   `
     $ ./_cryptoTestingApp
   `

4. This version is tested on Ubuntu 16.04/18.04 with SGX >=2.0


# Feedback
Email the authors: shangqi.lai@monash.edu, viet.vo@monash.edu, xingliang.yuan@monash.edu

# Reference
[1] Viet Vo, Shangqi Lai, Xingliang Yuan, Shi-Feng Sun, Surya Nepal, and Joseph K. Liu. 2020. Accelerating Forward and Backward Private Searchable Encryption Using Trusted Execution. In the 18th International Conference on Applied Cryptography and Network Security (ACNS), 2020. (Acceptance ratio: 21%)

[2] Ghous *Amjad*, Seny *Kamara*, and Tarik Moataz. 2019. Forward and Backward Private Searchable Encryption with SGX. In the 12th European Workshop on Systems Security (EuroSec), 2019.