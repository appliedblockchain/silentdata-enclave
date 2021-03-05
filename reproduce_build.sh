# Build the silentdata enclave with a reproducible MRENCLAVE value
# Download and prepare the code, build a docker image with a nix shell and launch the build.
#
# Usage:
#     ./reproduce_build.sh [ [ -d | --code-dir dir ] [ -o | --option option ] ]
#
# Options:
#     -d, --code-dir:
#         Specify the directory you want to download the repo. If this option is
#         not specified, will use the same directory as the script location.
#     -o, --option:
#         provision, build, all

set -e

script_dir="$(pwd)"

# Default values
code_dir="$script_dir/code_dir"
option="all"
branch="none"
copy_self="false"

# Set the directory names for all of the different packages
sgx_repo="$code_dir/sgx"
mbed_repo="$code_dir/mbedtls-compat-sgx"
enclave_repo="$code_dir/silentdata-enclave"

mount_dir="/linux-sgx"

parse_cmd()
{
    echo "parsing command"
    while [ "$1" != "" ]; do
        case $1 in
            -d | --code-dir ) shift
                code_dir="$1"
                ;;
            -o | --option ) shift
                option="$1"
                if [ "$option" != "all" ] && [ "$option" != "provision" ] && [ "$option" != "build" ]; then
                    exit 1
                fi
                ;;
            -b | --branch ) shift
                branch="$1"
                ;;
            -s | --self ) shift
                copy_self="true"
                ;;
            * )
                exit 1
        esac
        shift
    done
    echo "done parsing"
    mkdir -p "$code_dir" | exit
    # Reset the directory names in case the code_dir has changed
    code_dir="$(realpath $code_dir)"
    sgx_repo="$code_dir/sgx"
    mbed_repo="$code_dir/mbedtls-compat-sgx"
    enclave_repo="$code_dir/silentdata-enclave"
}

prepare_sgx_src()
{
    if [ -d $sgx_repo ]; then
        echo "Removing existing SGX code repo in $sgx_repo"
        rm -rf $sgx_repo
    fi

    git clone -b sgx_2.12_reproducible https://github.com/intel/linux-sgx.git $sgx_repo
    cd $sgx_repo && ./download_prebuilt.sh && cd -
}

prepare_sdk_installer()
{
    sdk_installer=sgx_linux_x64_sdk_reproducible_2.12.100.1.bin
    sdk_url=https://download.01.org/intel-sgx/sgx-linux/2.12/distro/nix_reproducibility/$sdk_installer
    cd $code_dir && wget $sdk_url && chmod +x $sdk_installer && cd -
}

prepare_mbedtls_sgx()
{
    if [ -d $mbed_repo ]; then
        echo "Removing existing mbedtls-compat-sgx code repo in $mbed_repo"
        rm -rf $mbed_repo
    fi
    git clone https://github.com/ffosilva/mbedtls-compat-sgx.git --recursive $mbed_repo
    pushd .
    cd $mbed_repo
    git checkout tags/2.24.0 -b v2_24_0
    git submodule update
    popd
}

prepare_silentdata()
{
    if [ -d $enclave_repo ]; then
        echo "Removing existing silentdata-enclave code repo in $enclave_repo"
        rm -rf $enclave_repo
    fi
    git clone https://github.com/appliedblockchain/silentdata-enclave.git $enclave_repo
    # Checkout a branch/commit if supplied
    if [ "$branch" != "none" ]; then
        pushd .
        cd $enclave_repo
        git checkout $branch
        popd
    fi
}

copy_silentdata()
{
    if [ -d $enclave_repo ]; then
        echo "Removing existing silentdata-enclave code repo in $enclave_repo"
        rm -rf $enclave_repo
    fi
    exclude_dir="$(realpath --relative-to=$script_dir $code_dir)"
    rsync -a --exclude=$exclude_dir ./* $enclave_repo
}

generate_cmd_script()
{
    rm -rf $code_dir/cmd.sh

    cat > $code_dir/cmd.sh << EOF
#!/usr/bin/env bash
. ~/.bash_profile
nix-shell ~/shell.nix --run "$mount_dir/start_build.sh"
EOF

    chmod +x $code_dir/cmd.sh
}

######################################################
# Step 1: Parse command line, prepare code and scripts
######################################################

parse_cmd $@

if [ "$option" == "provision" ] || [ "$option" == "all" ]; then

    prepare_sgx_src
    prepare_sdk_installer
    prepare_mbedtls_sgx
    if [ "$copy_self" == "true" ]; then
        copy_silentdata
    else
        prepare_silentdata
    fi

    cp $script_dir/print_mrenclave.py $code_dir
    cp $script_dir/start_build.sh.tmp $code_dir/start_build.sh
    chmod +x $code_dir/start_build.sh
    generate_cmd_script

fi

######################################################
# Step 2: Build docker image and launch the container
######################################################

if [ "$option" == "build" ] || [ "$option" == "all" ]; then

    # Check if the image already exists. If not, build the docker image
    set +e && docker image inspect silentdata-enclave-builder:latest > /dev/null 2>&1 && set -e
    if [ $? != 0 ]; then
        docker build -t silentdata-enclave-builder \
                     --build-arg https_proxy=$https_proxy \
                     --build-arg http_proxy=$http_proxy \
                     -f $script_dir/Dockerfile .
    fi

    docker run -v $code_dir:$mount_dir \
               -it \
               --network none \
               --rm silentdata-enclave-builder \
               /bin/bash -c $mount_dir/cmd.sh

fi

set +e
