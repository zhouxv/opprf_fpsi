FROM ubuntu:24.04

WORKDIR /home

# Install dependencies
RUN apt-get update && \
    apt-get install -y \
    vim \
    git \
    python3 \
    python3-pip \
    cmake \
    libgmp-dev \
    libspdlog-dev \
    libtool \
    nasm \
    libssl-dev \
    libmpfr-dev \
    iproute2 \
    net-tools \
    curl\
    jq  && \
    # install tcconfig for network interface configuration
    curl -sSL https://raw.githubusercontent.com/thombashi/tcconfig/master/scripts/installer.sh | bash

# upgrade gcc g++ to version 13
# RUN add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
#     apt-get update && \
#     apt-get install -y gcc-13 g++-13 && \
#     update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 90 && \
#     update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 90 && \
#     update-alternatives --set gcc /usr/bin/gcc-13 && \
#     update-alternatives --set g++ /usr/bin/g++-13

# Install thirdparty dependencies
COPY ./shell_install_all_dependencies.sh ./


RUN chmod +x ./*.sh && \
    ./shell_install_all_dependencies.sh

COPY ./shell_build_cmd.sh \
    ./CMakeLists.txt \
    ./

# Copy sourcode files and build executable file
COPY ./fpsi/ ./fpsi/
COPY ./frontend/ ./frontend/
RUN chmod +x ./*.sh && \
    ./shell_build_cmd.sh

# copy other files
COPY ./README.md \
    ./shell_run_bench_fpsi_low.sh \
    ./shell_run_bench_fpsi_high.sh \
    ./shell_run_bench_fmap.sh \
    ./

RUN chmod +x ./*.sh

