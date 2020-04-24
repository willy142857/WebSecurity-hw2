cmake_minimum_required(VERSION 3.10)

project(client)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${CMAKE_SOURCE_DIR})

add_executable(client ../../include/ssl.h ../../include/utility.h ../../include/exception.h client.cpp)
target_link_libraries(${PROJECT_NAME} -lstdc++fs OpenSSL::SSL OpenSSL::Crypto ${Boost_LIBRARIES} fmt::fmt)