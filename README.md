# silentdata-enclave
SGX enclave

## Reproducible build
- Make sure Docker is installed and working on your machine
```
docker run hello-world
```
- If not, follow the Docker installation [instructions](https://docs.docker.com/get-docker/) for your system
- Run the build script
```
source reproduce_build.sh
```
- The output directory can also be specified with `--code-dir`
- This script will: 
    - Prepare all of the code needed to build the enclave
    - Ceate a reproducible Docker container with a [Nix](https://nixos.org/manual/nix/stable/) shell
    - Build the SILENTDATA enclave in the container
    - Sign the enclave with a test private key
    - Extract the MRENCLAVE value from the signed enclave and print the value
- The printed MRENCLAVE can then be compared to the value in the Intel attestation to confirm that exactly the same code is being run
