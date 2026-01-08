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
target_link_libraries(main fmt::fmt)

# # ############################################
# # Link  libOTe                               #
# # ############################################
find_package(libOTe REQUIRED)
target_link_libraries(main oc::libOTe)

# # ############################################
# # Link  Myblake3                             #
# # ############################################
# # target_link_libraries: Used to specify the library files to be linked. However, directly using relative paths may cause issues.
target_link_libraries(main ${CMAKE_SOURCE_DIR}/out/install/lib/libblake3.a)

# # ############################################
# # Link  IPCL                                 #
# # ############################################
find_package(IPCL 2.0.0
    HINTS
    REQUIRED)
target_link_libraries(main IPCL::ipcl)


# # ############################################
# # Link  GMP                                  #
# # ############################################
target_link_libraries(main /lib/x86_64-linux-gnu/libgmpxx.a /lib/x86_64-linux-gnu/libgmp.a)


