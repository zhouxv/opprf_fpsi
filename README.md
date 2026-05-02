# Breaking the Exponential Barrier: Fuzzy PSI with Linear Complexity from Symmetric-Key Primitives

Private Set Intersection (PSI) is a widely used cryptographic primitive that enables two parties to compute the intersection of their private sets without revealing any information about items not in the intersection.

We propose a fuzzy PSI protocol for $L_{p \in [1,+\infty]}$ distance based on symmetric-key primitives. It leverages new fuzzy matching and mapping variants to achieve linear complexity in $d$ and $\log\delta$.

## 1. Project Structure

The following is the structure description of this project. We have provided some scripts to assist with building and running tests. Please grant execute permissions to these scripts, all of which are designed to be run from the project root directory.

```bash
├── fpsi/                               # Core FPSI protocol implementation
│   ├── config.h                        # Configuration header
│   ├── fpsi_base.h                     # Base definitions
│   ├── fpsi_protocol.*                 # Main protocol logic
│   ├── fpsi_sender.*                   # Sender implementation
│   ├── fpsi_recv.*                     # Receiver implementation
│   ├── cmp_fmap/                       # Fuzzy mapping (Fmap) implementation
│   ├── opprf/                          # OPPRF (Oblivious Programmable PRF) primitives
│   ├── pis_new/                        # Private Information System (new version)
│   ├── rb_okvs/                        # Rb OKVS (Oblivious Key-Value Store)
│   └── utils/                          # Utility functions
├── frontend/                           # Frontend and testing
│   ├── main.cpp                        # Main entry point for benchmarks
│   ├── test.*                          # Test files
├── CMakeLists.txt                      # CMake configuration
├── Dockerfile                          # Docker image definition
├── shell_build_cmd.sh                  # Build script
├── shell_install_all_dependencies.sh   # Dependency installation script
├── shell_run_bench_fmap.sh             # Fmap benchmark script (reproduces Table 3 data in our paper)
├── shell_run_bench_fpsi_high.sh        # FPSI benchmark for high-dimensional data (reproduces Table 4 data in our paper)
└── shell_run_bench_fpsi_low.sh         # FPSI benchmark for low-dimensional data (reproduces Table 7 data in our paper)
```

## 2. Prerequisites

**Supported OS :** `Ubuntu 20.04+` meet all project runtime specifications.

**Memory :** `100GB or above recommended`. Peak memory usage during image build ranges from 66GB to 80GB, which can cause out-of-memory issues on machines with less than 64 GB RAM. Please ensure sufficient memory is available before proceeding.

**Docker Version :** `Docker 28.3.3+`  (Earlier versions have not been validated).

**Dependencies :** local build must install the following dependencies :

```bash
gcc13           # required to ensure full *C++20* support
cmake >= 3.22   # cmake_minimum_required
git
python3
python3-pip
libgmp-dev
libspdlog-dev
libssl-dev
libmpfr-dev
libfmt-dev
libtool
nasm
```

## 3. Docker Build and Run benchmarks

### Step 1: Obtain Docker Image of our Protocol

*Option 1 : Build the image locally.*

```bash
# build docker image and run the docker container with the necessary capabilities
docker build -t fpsi_opprf:latest .
docker run -dit --name fpsi_opprf --cap-add=NET_ADMIN fpsi_opprf:latest
```

*Option 2 : Pull the latest image directly from Docker Hub public repository using the following command:*

```bash
# pull image from Docker Hub
docker pull blueobsidian/fpsi_opprf:latest
docker run -dit --name fpsi_opprf --cap-add=NET_ADMIN blueobsidian/fpsi_opprf:latest
```

### Step 2: Run Benchmark Scripts

```bash
# Reproduces Table 3 data in our paper (FMAP benchmarks)
./shell_run_bench_fmap.sh
# Reproduces Table 4 data in our paper (FPSI in high dimension case benchmarks)
./shell_run_bench_fpsi_high.sh
# Reproduces Table 7 data in our paper (FPSI in low dimension case benchmarks)
./shell_run_bench_fpsi_low.sh 
```

## 4. Usage Guide for Executable

This section describes the usage of the executable file located at `./build/main`.

### Command-Line Options

| Flag | Meaning | Optional Values | Description |
|:----:|:--------|:----------------|:------------|
| **p** | Protocol Type | `1`: (1-1)-FMAP protocol<br/>(*fig7 in our paper*) (default)<br/>`2`: FPSI protocol | Select which protocol to run |
| **n** | Set Size (logarithm) | Positive integer(s), default: `8` | Input set size = 2^n |
| **d** | Dimension | Positive integer(s), default: `2` | Dimension of the points |
| **m** | Metric | `0`: L∞ (default)<br/>`1`: L₁<br/>`2`: L₂ | Distance metric for fuzzy matching |
| **delta** | Radius/Threshold | `10`, `30`, `60`, `120`, `250` | Distance threshold δ.  |
| **i** | Intersection Size | Positive integer, default: `15` | Number of points in the intersection |
| **fm** | Fmap Type | `0`: cmp_fmap<br/>`1`: spatial_hash_fmap (default)<br/> | Fuzzy mapping variant to use, only for FPSI protocol |
| **ip** | Server IP | IP address string, default: `"127.0.0.1"` | IP address for network communication |
| **port** | Server Port | Port number, default: `1212` | Starting port number for connections |
| **trait** | Number of Trials | Positive integer, default: `1` | Number of test runs for averaging results |
| **detail** | Detailed Output | Flag (no value) | If set, print detailed timing and communication breakdown |
| **log** | Log Level | `0`: off<br/>`1`: info (default)<br/>`2`: debug | Console logging verbosity |

### Usage Examples

#### Example A: Run FMAP benchmark

```bash
./build/main -p 1 -n 12 -d 6 -delta 60  -trait 5 -log 0
# Protocol: FMAP
# Set size: 2^12 = 4096 points
# Dimension: 6
# Threshold: δ=60
# Trials: 5
```

#### Example B: FPSI low-dimensional run

```bash
./build/main -p 2 -trait 3 -log 0 -i 11 -d 2 -delta 10 -n 8 -m 0 -fm 1
# Protocol: FPSI
# Set size: 2^8 = 256 points
# Dimension: 2 (low-dim)
# Metric: L∞ (m=0)
# Threshold: δ=10
# Fmap variant: spatial_hash (fm=1)
# Trials: 3
```

#### Example C: FPSI high-dimensional run

```bash
./build/main -p 2 -trait 3 -log 0 -i 11 -d 10 -delta 60 -n 12 -m 1 -fm 0
# Protocol: FPSI
# Set size: 2^12 = 4096 points
# Dimension: 10 (high-dim)
# Metric: L1 (m=1)
# Threshold: δ=60
# Fmap variant: cmp_fmap (fm=0)
# Trials: 3
```
