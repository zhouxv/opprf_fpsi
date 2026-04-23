cmake_minimum_required(VERSION 3.22)
project(ourFPSI)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED YES)

set(CMAKE_PREFIX_PATH "${CMAKE_SOURCE_DIR}/out/install")

# include_directories：Used to specify the search path for header files, rather than the path for library files
include_directories(fpsi)
include_directories(frontend)
include_directories(${CMAKE_SOURCE_DIR}/out/install/include)

file(GLOB_RECURSE SRCS
    frontend/*.cpp
    fpsi/*.cpp
)

add_executable(main ${SRCS})


target_compile_options(main PRIVATE
    $<$<CONFIG:Debug>:-g -O0 -fno-omit-frame-pointer>
    $<$<CONFIG:Release>:-O3 -DNDEBUG>
)

# ############################################
# Link  fmt                                  #
# ############################################
find_package(fmt REQUIRED)
target_link_libraries(main PUBLIC fmt::fmt)

# # ############################################
# # Link  libOTe                               #
# # ############################################
find_package(libOTe REQUIRED)
target_link_libraries(main PUBLIC oc::libOTe)

# # ############################################
# # Link  IPCL                                 #
# # ############################################
find_package(IPCL 2.0.0
    HINTS
    REQUIRED)
target_link_libraries(main PUBLIC IPCL::ipcl)

# # ############################################
# # Link  Myblake3                             #
# # ############################################
add_library(blake3 STATIC IMPORTED)
set_target_properties(blake3 PROPERTIES
    IMPORTED_LOCATION "${CMAKE_SOURCE_DIR}/out/install/lib/libblake3.a"
)
target_link_libraries(main PUBLIC blake3)

# # ############################################
# # Link  GMP                                  #
# # ############################################
add_library(gmp STATIC IMPORTED)
set_target_properties(gmp PROPERTIES
    IMPORTED_LOCATION "/lib/x86_64-linux-gnu/libgmp.a"
)
target_link_libraries(main PUBLIC gmp)

