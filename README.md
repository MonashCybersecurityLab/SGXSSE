# SE_SGX_1 and SE_SGX_2

The repository includes forward and type-II backward private SSE schemes, SGX_SE1 and SGX_SE2, with trusted execution.

# SE_SGX_1

## How to Build/Execute the Application 
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

## Worklog after Fork:
Mon 4 Mar, 19
- This version is only tested on Ubuntu 16.04/18.04 with SGX >=2.0

# SE_SGX_2

## How to Build/Execute the Application 
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

## Worklog after Fork:
Mon 4 Mar, 19
- This version is only tested on Ubuntu 16.04/18.04 with SGX >=2.0

