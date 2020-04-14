# Bunker-B

## How to Build/Execute the Application 

1. Install Intel(R) SGX SDK for Linux* OS

2. Build the project with the prepared Makefile:

   Using Hardware Mode, Pre-release build:
      ``$ cd Bunker-B && make SGX_MODE=HW SGX_PRERELEASE=1``

3. Execute the binary directly:
   `
     $ ./_cryptoTestingApp
   `

4. This version is tested on Ubuntu 16.04/18.04 with SGX >=2.0

## Worklog after Fork:

Mon 4 Mar, 19

- This version is only tested on Ubuntu 16.04/18.04 with SGX >=2.0