cmake_minimum_required(VERSION 3.14)
project(SearchableEncryption CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include(FetchContent)

FetchContent_Declare(
    openssl
    URL https://www.openssl.org/source/old/3.0/openssl-3.0.8.tar.gz
    URL_HASH SHA256=6c13d2bf38fdf31eac3ce2a347073673f5d63263398f1f69d0df4a41253e4b3e
)

FetchContent_MakeAvailable(openssl)

add_subdirectory(src)