cmake_minimum_required(VERSION 3.7)

project(SimpleRSADigest)

set(CMAKE_C_STANDARD 11)

set(SOURCE_FILES main.c)

add_executable(SimpleRSADigest ${SOURCE_FILES})
target_link_libraries(SimpleRSADigest gmp)