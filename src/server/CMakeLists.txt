cmake_minimum_required(VERSION 3.10)

project(server)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

include_directories(${CMAKE_SOURCE_DIR})

add_executable(server ../../include/ssl.h ../../include/utility.h ../../include/exception.h server.cpp)
target_link_libraries(${PROJECT_NAME} -lpthread OpenSSL::SSL OpenSSL::Crypto ${Boost_LIBRARIES} fmt::fmt)
