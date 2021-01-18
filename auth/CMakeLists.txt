cmake_minimum_required(VERSION 3.17)
project(authlib C)

set(CMAKE_C_STANDARD 99)

include_directories(tinycrypt/lib/include)
include_directories(include hal)

file(GLOB AUTH_SRC ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c ${CMAKE_CURRENT_SOURCE_DIR}/hal/auth_hal_if.c )

add_library(authlib ${AUTH_SRC})