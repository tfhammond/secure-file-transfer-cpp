cmake_minimum_required(VERSION 3.10)
project(secure-file-transfer-cpp VERSION 0.1 LANGUAGES CXX)

# Require C++17 or newer
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Find OpenSSL for encryption
find_package(OpenSSL REQUIRED)

# Include headers from the include/ directory
include_directories(${CMAKE_SOURCE_DIR}/include)

# Build "encrypt" executable
add_executable(secureft
    src/main.cpp
    src/encrypt.cpp
    src/decrypt.cpp
)
target_link_libraries(secureft PRIVATE OpenSSL::Crypto)
