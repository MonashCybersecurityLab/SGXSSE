# Introduction

We design and implement two forward and backward private SE schemes, named \textsf{SGX-SE1} and \textsf{SGX-SE2}. By using SGX, the  communication cost between the client and server of achieving forward and backward privacy in SE is significantly reduced. 

Both \textsf{SGX-SE1} and \textsf{SGX-SE2} leverage the SGX enclave to carefully track keyword states and document deletions, in order to minimise the communication overhead between the SGX and untrusted memory. In particular, \textsf{SGX-SE2} is an optimised version of \textsf{SGX-SE1} by employing Bloom filter to compress the information of deletions, which speeds up the search operations and  boosts the capacity of batch processing in addition and deletion.

# SE_SGX_1 Execution

1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:

Using Hardware Mode, Pre-release build:
`
    Direct to SGX_SE1, then
`
    $ make SGX_MODE=HW SGX_PRERELEASE=1

3. Execute the binary directly:
`
    $ ./_cryptoTestingApp
`

4. This version is only tested on Ubuntu 16.04/18.04 with SGX >=2.0

# SE_SGX_2 Execution

1. Install Intel(R) SGX SDK for Linux* OS
2. Build the project with the prepared Makefile:


Using Hardware Mode, Pre-release build:
`
    Direct to SGX_SE2, then
`
    $ make SGX_MODE=HW SGX_PRERELEASE=1

3. Execute the binary directly:
`
    $ ./_cryptoTestingApp
`

4. This version is only tested on Ubuntu 16.04/18.04 with SGX >=2.0


# Feedback
Email the authors: shangqi.lai@monash.edu, viet.vo@monash.edu

