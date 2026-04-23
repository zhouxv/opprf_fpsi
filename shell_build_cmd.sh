#! /bin/bash
set -e
# This script is used to build the project using CMake and Make.

mkdir -p build && cd build

printf "Building the project with CMake and Make...\n"
# cmake .. -DCMAKE_BUILD_TYPE=Debug
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)
printf "Buidling completed successfully! You can find the built artifacts in the 'build' directory.\n"