cmake_minimum_required(VERSION 3.7)

project(SimpleRSADigest)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS -Wall)
set(CMAKE_C_FLAGS -Wextra)

set(SOURCE_FILES main.c gmp_helper.c gmp_helper.h rsa.h rsa_keygen.c rsa_crypto.c sha512.c sha512.h misc_helper.c misc_helper.h)

add_executable(SimpleRSADigest ${SOURCE_FILES})
target_link_libraries(SimpleRSADigest gmp)