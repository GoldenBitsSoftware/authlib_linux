cmake_minimum_required(VERSION 3.17)
project(auth_sample C)

set(CMAKE_C_STANDARD 99)

include_directories(auth/include)
include_directories(auth/hal)

add_subdirectory(auth)
link_directories(auth)

add_executable(auth_sample main.c)

target_link_libraries(auth_sample authlib tinycrypt.a -lpthread)

