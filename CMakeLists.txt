cmake_minimum_required(VERSION 3.10)
project(wallet)

set(CMAKE_BUILD_TYPE Debug)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -g")

# Find OpenSSL
find_package(OpenSSL REQUIRED)

# Include the JSON library directly
include_directories(${CMAKE_SOURCE_DIR}/include)

# First, create the library
add_library(wallet_lib
    src/error.hpp
    src/base58.hpp
    src/base58.cpp
    src/wallet_state.cpp
    src/key_deserializer.cpp
    src/bip32_util.cpp
    src/bitcoin_cli.cpp
    src/segwit.hpp
    src/segwit.cpp
    src/wallet.hpp
    src/wallet.cpp
    src/hash_utils.cpp
)

# Set include directories for the library
target_include_directories(wallet_lib
    PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}
)

# Link against OpenSSL
target_link_libraries(wallet_lib
    PRIVATE
    OpenSSL::Crypto
    crypto
)

# Create the executable and link it with the library
add_executable(wallet
    src/main.cpp
)

# Link the executable with wallet_lib
target_link_libraries(wallet
    PRIVATE
    wallet_lib
)

# Update test configurations
if(BUILD_TESTING)
    add_executable(wallet_tests
        tests/wallet_tests.cpp
        # ... other test files ...
    )
    target_link_libraries(wallet_tests
        PRIVATE
        wallet_lib
        GTest::gtest
        GTest::gtest_main
    )
endif() 