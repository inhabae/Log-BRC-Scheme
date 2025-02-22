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

int main() {
    std::vector<unsigned char> key(32, 0x01);
    int original_tid = 10001;
    auto ciphertext = Encrypt(key, original_tid);
    int decrypted_tid = Decrypt(key, ciphertext);
    std::cout << "Original tid: " << original_tid << ", Decrypted tid: " << decrypted_tid << "\n";
    return 0;
}
