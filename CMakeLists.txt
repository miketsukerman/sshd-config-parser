cmake_minimum_required(VERSION 3.28)
project(SshdConfigPegtlParser)

set(CMAKE_CXX_STANDARD 17)

add_executable(SshdConfigPegtlParser main.cpp)

# add dependencies
include(cmake/CPM.cmake)

set(BUILD_OPENSSL ON)
set(OPENSSL_BUILD_VERSION "1.1.1w")

CPMAddPackage("gh:taocpp/PEGTL#3.2.7")
CPMAddPackage("gh:viaduck/openssl-cmake#v1")

# find_package(OpenSSL REQUIRED)

# link dependencies
target_link_libraries(SshdConfigPegtlParser taocpp::pegtl ssl crypto)
