cmake_minimum_required(VERSION 3.10)

project(hashSum)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

find_package(OpenSSL REQUIRED)
find_package(Threads REQUIRED)

add_executable(hashSum HashSum.cpp)

target_link_libraries(hashSum PRIVATE OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
