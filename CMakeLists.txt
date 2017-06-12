cmake_minimum_required(VERSION 3.7)

project(SimpleRSADigest)

set(CMAKE_C_STANDARD 11)

set(CMAKE_C_FLAGS -Wall)

set(SOURCE_FILES main.c gmp_helper.c gmp_helper.h rsa.c rsa_digest.h)

add_executable(SimpleRSADigest ${SOURCE_FILES})
target_link_libraries(SimpleRSADigest gmp)