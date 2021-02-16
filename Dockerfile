# Copyright (C) 2011-2020 Intel Corporation. All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions
# are met:
#
#   * Redistributions of source code must retain the above copyright
#     notice, this list of conditions and the following disclaimer.
#   * Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in
#     the documentation and/or other materials provided with the
#     distribution.
#   * Neither the name of Intel Corporation nor the names of its
#     contributors may be used to endorse or promote products derived
#     from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
# A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
# OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
# LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
# THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
# OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

FROM ubuntu:20.04
ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
        && apt-get install -y curl python perl git docker sudo \
        && mkdir -p /nix /etc/nix \
        && chmod a+rwx /nix \
        && echo 'sandbox = false' > /etc/nix/nix.conf \
        && rm -rf /var/lib/apt/lists/*

#add a user for Nix
RUN adduser user --home /home/user --disabled-password --gecos "" --shell /bin/bash
RUN adduser user sudo
RUN echo '%sudo ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers
CMD /bin/bash -l
USER user
ENV USER user
WORKDIR /home/user

#create the shell config
RUN echo "{ pkgs ? import <nixpkgs> {} }: \n\
with pkgs; \n\
\n\
stdenvNoCC.mkDerivation { \n\
\tname = \"sgx-build-nix\"; \n\
\tbuildInputs = [ \n\
\t\t/nix/store/raiq8qv61rc66arg3vzyfr9kw83s7dwv-autoconf-2.69 \n\
\t\t/nix/store/7bsq9c4z657hddv60hpks48ws699y0fc-automake-1.16.1 \n\
\t\t/nix/store/idj0yrdlk8x49f3gyl4sb8divwhfgjvp-libtool-2.4.6 \n\
\t\t/nix/store/68yb6ams241kf5pjyxiwd7a98xxcbx0r-ocaml-4.06.1 \n\
\t\t/nix/store/ncqmw9iybd6iwxd4yk1x57gvs76k1sq4-ocamlbuild-0.12.0 \n\
\t\t/nix/store/9dkhfaw1qsmvw4rv1z1fqgwhfpbdqrn0-file-5.35 \n\
\t\t/nix/store/vs700jsqx2465qr0x78zcmgiii0890n3-cmake-3.15.5 \n\
\t\t/nix/store/d0fv0g4vcv4s0ysa81pn9sf6fy4zzjcv-gnum4-1.4.18 \n\
\t\t/nix/store/ljvpvjh36h9x2aaqzaby5clclq4mgdmc-openssl-1.1.1b \n\
\t\t/nix/store/0klr6d4k2g0kabkamfivg185wpx8biqv-openssl-1.1.1b-dev \n\
\t\t/nix/store/yg76yir7rkxkfz6p77w4vjasi3cgc0q6-gnumake-4.2.1 \n\
\t\t/nix/store/5lyvydxv0w4f2s1ba84pjlbpvqkgn1ni-linux-headers-4.19.16 \n\
\t\t/nix/store/681354n3k44r8z90m35hm8945vsp95h1-glibc-2.27 \n\
\t\t/nix/store/1kl6ms8x56iyhylb2r83lq7j3jbnix7w-binutils-2.31.1 \n\
\t\t/nix/store/lvwq3g3093injr86lm0kp0f61k5cbpay-gcc-wrapper-8.3.0 \n\
\t\t/nix/store/dmxxhhl5yr92pbl17q1szvx34jcbzsy8-texinfo-6.5 \n\
\t\t/nix/store/g6c80c9s2hmrk7jmkp9przi83jpcs8c6-bison-3.5.4 \n\
\t\t/nix/store/qh2ppjlz4yq65cl0vs0m2h57x2cjlwm4-flex-2.6.4 \n\
\t]; \n\
\n\
\tshellHook = '' \n\
\techo \"SGX build enviroment\" \n\
\t''; \n\
} \n\
" > /home/user/shell.nix

#install the required software
RUN touch .bash_profile \
&& curl https://nixos.org/releases/nix/nix-2.2.1/install | sh \
&& . /home/user/.nix-profile/etc/profile.d/nix.sh \
&& nix-env -i /nix/store/raiq8qv61rc66arg3vzyfr9kw83s7dwv-autoconf-2.69 \
&& nix-env -i /nix/store/7bsq9c4z657hddv60hpks48ws699y0fc-automake-1.16.1 \
&& nix-env -i /nix/store/idj0yrdlk8x49f3gyl4sb8divwhfgjvp-libtool-2.4.6 \
&& nix-env -i /nix/store/68yb6ams241kf5pjyxiwd7a98xxcbx0r-ocaml-4.06.1 \
&& nix-env -i /nix/store/ncqmw9iybd6iwxd4yk1x57gvs76k1sq4-ocamlbuild-0.12.0 \
&& nix-env -i /nix/store/9dkhfaw1qsmvw4rv1z1fqgwhfpbdqrn0-file-5.35 \
&& nix-env -i /nix/store/vs700jsqx2465qr0x78zcmgiii0890n3-cmake-3.15.5 \
&& nix-env -i /nix/store/d0fv0g4vcv4s0ysa81pn9sf6fy4zzjcv-gnum4-1.4.18 \
&& nix-env -i /nix/store/ljvpvjh36h9x2aaqzaby5clclq4mgdmc-openssl-1.1.1b \
&& nix-env -i /nix/store/0klr6d4k2g0kabkamfivg185wpx8biqv-openssl-1.1.1b-dev \
&& nix-env -i /nix/store/yg76yir7rkxkfz6p77w4vjasi3cgc0q6-gnumake-4.2.1 \
&& nix-env -i /nix/store/5lyvydxv0w4f2s1ba84pjlbpvqkgn1ni-linux-headers-4.19.16 \
&& nix-env -i /nix/store/681354n3k44r8z90m35hm8945vsp95h1-glibc-2.27 \
&& nix-env -i /nix/store/1kl6ms8x56iyhylb2r83lq7j3jbnix7w-binutils-2.31.1 \
&& nix-env --set-flag priority 10 binutils-2.31.1 \
&& nix-env -i /nix/store/lvwq3g3093injr86lm0kp0f61k5cbpay-gcc-wrapper-8.3.0 \
&& nix-env -i /nix/store/dmxxhhl5yr92pbl17q1szvx34jcbzsy8-texinfo-6.5 \
&& nix-env -i /nix/store/g6c80c9s2hmrk7jmkp9przi83jpcs8c6-bison-3.5.4 \
&& nix-env -i /nix/store/qh2ppjlz4yq65cl0vs0m2h57x2cjlwm4-flex-2.6.4


#config nix-shell
RUN . /home/user/.nix-profile/etc/profile.d/nix.sh \
&& nix-shell

