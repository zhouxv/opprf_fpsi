FROM ubuntu:22.04

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
    software-properties-common && \
    # install tcconfig for network interface configuration
    pip install tcconfig

# upgrade gcc g++ to version 13
RUN add-apt-repository ppa:ubuntu-toolchain-r/test -y && \
    apt-get update && \
    apt-get install -y gcc-13 g++-13 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-13 90 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-13 90 && \
    update-alternatives --set gcc /usr/bin/gcc-13 && \
    update-alternatives --set g++ /usr/bin/g++-13

# Install thirdparty dependencies
COPY ./shell_install_all_dependencies.sh ./


RUN chmod +x ./*.sh && \
    ./shell_install_all_dependencies.sh

COPY ./shell_build_cmd.sh \
    ./CMakeLists.txt \
    ./

# Copying sourcode files
COPY ./fpsi/ ./fpsi/
COPY ./frontend/ ./frontend/

RUN chmod +x ./*.sh && \
    ./shell_build_cmd.sh

COPY ./README.md ./
COPY ./shell_run_bench_fmap.sh ./shell_run_bench_fmap.sh
COPY ./shell_run_bench_fpsi.sh ./shell_run_bench_fpsi.sh

RUN chmod +x ./*.sh

