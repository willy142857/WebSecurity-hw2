cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(Boost_USE_STATIC_LIBS ON)

find_package(OpenSSL REQUIRED)
find_package(Boost COMPONENTS system)
find_package(Fmt)
include_directories(${Boost_INCLUDE_DIR})

add_subdirectory(server)
add_subdirectory(client)