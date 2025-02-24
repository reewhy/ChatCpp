cmake_minimum_required(VERSION 3.30)
project(CppServer)

set(CMAKE_CXX_STANDARD 20)

add_executable(CppServer main.cpp)

target_link_libraries(CppServer ws2_32)