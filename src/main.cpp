#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdexcept>
#include <vector>
#include <map>
#include <string>
#include <iostream>
#include <iomanip>

struct Tuple {
    int tid;
    int age;
};

std::vector<unsigned char> PRF(const std::vector<unsigned char>& key, const std::string& data) {
    unsigned char* result = nullptr;
    unsigned int len = 32;
    result = HMAC(EVP_sha256(), key.data(), key.size(),
                  reinterpret_cast<const unsigned char*>(data.c_str()), data.size(), nullptr, &len);
    if (!result) {
        throw std::runtime_error("HMAC failed");
    }
    return std::vector<unsigned char>(result, result + len);
}

int main() {
    std::vector<unsigned char> key(32, 0x01);
    auto prf_result = PRF(key, "test");

    for (auto byte : prf_result) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte << std::endl;
    }

    std::cout << std::hex << "PRF computed successfully\n";
    return 0;
}
