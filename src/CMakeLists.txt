add_executable(main main.cpp)

find_package(OpenSSL REQUIRED)

target_link_libraries(main PRIVATE OpenSSL::SSL OpenSSL::Crypto)

target_include_directories(main PRIVATE ${OPENSSL_INCLUDE_DIR})