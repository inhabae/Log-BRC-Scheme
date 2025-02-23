#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <stdexcept>
#include <vector>
#include <map>
#include <string>
#include <iostream>
#include <iomanip>

// #include "LogBrc.h"

struct Tuple {
    int tid;
    int age;
};

// Computes a pseudorandom function using HMAC-SHA256
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

// Encrypts a 32-bit integer using AES-256 in CTR mode
std::vector<unsigned char> Encrypt(const std::vector<unsigned char>& key, int tid) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    std::vector<unsigned char> ciphertext(sizeof(tid));
    int len, plaintext_len = sizeof(tid);
    unsigned char iv[16] = {0};

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptInit_ex failed");
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                               reinterpret_cast<unsigned char*>(&tid), plaintext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptUpdate failed");
    }
    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_EncryptFinal_ex failed");
    }
    EVP_CIPHER_CTX_free(ctx);
    return ciphertext;
}

// Decrypts a 4-byte ciphertext into a 32-bit integer using AES-256 in CTR mode
int Decrypt(const std::vector<unsigned char>& key, const std::vector<unsigned char>& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
    int tid, len, ciphertext_len = ciphertext.size();
    unsigned char iv[16] = {0};

    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key.data(), iv)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptInit_ex failed");
    }
    if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&tid), &len,
                               ciphertext.data(), ciphertext_len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptUpdate failed");
    }
    if (1 != EVP_DecryptFinal_ex(ctx, reinterpret_cast<unsigned char*>(&tid) + len, &len)) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("EVP_DecryptFinal_ex failed");
    }
    EVP_CIPHER_CTX_free(ctx);
    return tid;
}

std::map<std::vector<unsigned char>, std::vector<unsigned char>> SetupPiBas(
    const std::vector<Tuple>& database, const std::vector<unsigned char>& key) {
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> ED;
    std::map<int, std::vector<int>> age_to_ids;

    // Group tuple IDs by age
    for (const auto& tuple : database) {
        age_to_ids[tuple.age].push_back(tuple.tid);
    }

    // Encrypt each age group with derived keys
    for (const auto& [age, ids] : age_to_ids) {
        std::string w = std::to_string(age);
        auto K1K2 = PRF(key, w);
        std::vector<unsigned char> K1(K1K2.begin(), K1K2.begin() + 16);
        std::vector<unsigned char> K2(K1K2.begin() + 16, K1K2.end());

        int counter = 0;
        for (int tid : ids) {
            auto label = PRF(K1, std::to_string(counter++));
            auto ciphertext = Encrypt(K2, tid);
            ED[label] = ciphertext;
        }
    }
    return ED;
}

std::vector<int> SearchPiBas(const std::map<std::vector<unsigned char>, std::vector<unsigned char>>& ED,
    const std::vector<unsigned char>& key, int age) {
    std::vector<int> result;
    std::string w = std::to_string(age);
    auto K1K2 = PRF(key, w);
    std::vector<unsigned char> K1(K1K2.begin(), K1K2.begin() + 16);
    std::vector<unsigned char> K2(K1K2.begin() + 16, K1K2.end());

    int counter = 0;
    while (true) {
    auto label = PRF(K1, std::to_string(counter++));
    auto it = ED.find(label);
    if (it == ED.end()) break;
    result.push_back(Decrypt(K2, it->second));
    }
    return result;
}

std::vector<int> RangeSearchPiBas(
    const std::map<std::vector<unsigned char>, std::vector<unsigned char>>& ED, 
    const std::vector<unsigned char>& key, int low, int high) {
        std::vector<int> result;
        for (int age = low; age <= high; ++age) {
            auto ids = SearchPiBas(ED, key, age);
            result.insert(result.end(), ids.begin(), ids.end());
            }
        return result;
}

// Logarithmic-BRC Setup
struct LogBRCIndex {
    std::map<std::vector<unsigned char>, std::vector<unsigned char>> index;
};

LogBRCIndex SetupLogBRC(const std::vector<Tuple>& database, const std::vector<unsigned char>& key, int domain_size) {
    LogBRCIndex index;
    std::map<std::string, std::vector<int>> dyadic_to_ids;

    for (const auto& tuple : database) {
        int v = tuple.age;
        for (int l = 0; l < std::log2(domain_size); ++l) {
            int size = 1 << l;
            int start = (v / size) * size;
            int end = start + size - 1;
            std::string range = std::to_string(start) + "-" + std::to_string(end);
            dyadic_to_ids[range].push_back(tuple.tid);
        }
    }

    for (const auto& [range, ids] : dyadic_to_ids) {
        auto K1K2 = PRF(key, range);
        std::vector<unsigned char> K1(K1K2.begin(), K1K2.begin() + 16);
        std::vector<unsigned char> K2(K1K2.begin() + 16, K1K2.end());

        int counter = 0;
        for (int tid : ids) {
            auto label = PRF(K1, std::to_string(counter++));
            auto ciphertext = Encrypt(K2, tid);
            index.index[label] = ciphertext;
        }
    }
    return index;
}

// helper function
void printVector(const std::vector<unsigned char>& vec) {
    std::cout << "{ ";
    for (unsigned char c : vec) {
        std::cout << static_cast<int>(c) << " ";
    }
    std::cout << "}";
}


int main() {
    std::vector<Tuple> database = { {1, 25}, {2, 30}, {3, 25} };
    std::vector<unsigned char> key(32, 0x01);

    auto ED = SetupPiBas(database, key);
    std::cout << "# of PiBas entries: " << ED.size() << "\n";

    // for (const auto& pair : ED) {
    //     std::cout << "Key: ";
    //     printVector(pair.first);
    //     std::cout << " -> Value: ";
    //     printVector(pair.second);
    //     std::cout << std::endl;
    // }

    // auto result = RangeSearchPiBas(ED, key, 27, 31);
    // std::cout << "Found " << result.size() << " entries in range [27,31]\n";
    // result = RangeSearchPiBas(ED, key, 24, 31);
    // std::cout << "Found " << result.size() << " entries in range [24,31]\n";
    // result = RangeSearchPiBas(ED, key, 20, 21);
    // std::cout << "Found " << result.size() << " entries in range [20,21]\n";

    int domain_size = 100;
    auto ind = SetupLogBRC(database, key, domain_size);
    std::cout << "LogBRC setup complete, index entries: " << ind.index.size() << "\n";
    for (const auto& pair : ind.index) {  // Access 'index' inside 'ind'
        std::cout << "Key: ";
        printVector(pair.first);
        std::cout << " -> Value: ";
        printVector(pair.second);
        std::cout << std::endl;
    }
    return 0;
}