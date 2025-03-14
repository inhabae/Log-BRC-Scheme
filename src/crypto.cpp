#include "crypto.h"

#include <openssl/err.h>

#include <cstring>
#include <iomanip>
#include <sstream>
#include <stdexcept>

namespace CryptoUtils {
void prf(const unsigned char* key, int key_len, const std::string& data,
         unsigned char* output) {
  unsigned int digest_len = LABEL_SIZE;
  HMAC(EVP_sha256(), key, key_len,
       reinterpret_cast<const unsigned char*>(data.c_str()), data.length(),
       output, &digest_len);
  if (digest_len != LABEL_SIZE) {
    throw std::runtime_error("PRF output length mismatch");
  }
}

std::string encryptTupleID(const unsigned char* key, int tupleID,
                           unsigned char* iv) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("Failed to create cipher context");

  if (EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to initialize encryption");
  }

  unsigned char plaintext[sizeof(int)];
  std::memcpy(plaintext, &tupleID, sizeof(int));

  unsigned char ciphertext[sizeof(int) + EVP_MAX_BLOCK_LENGTH];
  int ciphertext_len;
  if (EVP_EncryptUpdate(ctx, ciphertext, &ciphertext_len, plaintext,
                        sizeof(int)) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to encrypt tuple ID");
  }

  int final_len;
  if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to finalize encryption");
  }
  ciphertext_len += final_len;

  EVP_CIPHER_CTX_free(ctx);

  std::string result;
  result.append(reinterpret_cast<char*>(iv), IV_SIZE);
  result.append(reinterpret_cast<char*>(ciphertext), ciphertext_len);
  return result;
}

int decryptTupleID(const unsigned char* key, const std::string& encryptedData,
                   unsigned char* iv) {
  if (encryptedData.length() < IV_SIZE + sizeof(int)) {
    throw std::runtime_error("Encrypted data too short");
  }
  std::memcpy(iv, encryptedData.c_str(), IV_SIZE);
  const unsigned char* ciphertext =
      reinterpret_cast<const unsigned char*>(encryptedData.c_str()) + IV_SIZE;
  int ciphertext_len = encryptedData.length() - IV_SIZE;

  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("Failed to create cipher context");

  if (EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), nullptr, key, iv) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to initialize decryption");
  }

  unsigned char plaintext[sizeof(int) + EVP_MAX_BLOCK_LENGTH];
  int plaintext_len;
  if (EVP_DecryptUpdate(ctx, plaintext, &plaintext_len, ciphertext,
                        ciphertext_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to decrypt tuple ID");
  }

  int final_len;
  if (EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &final_len) != 1) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("Failed to finalize decryption");
  }
  plaintext_len += final_len;

  EVP_CIPHER_CTX_free(ctx);

  int tupleID;
  std::memcpy(&tupleID, plaintext, sizeof(int));
  return tupleID;
}

void generateKey(unsigned char* key) {
  if (RAND_bytes(key, KEY_SIZE) != 1) {
    throw std::runtime_error("Failed to generate random key");
  }
}

std::string digestToHex(const unsigned char* digest, int len) {
  std::stringstream ss;
  for (int i = 0; i < len; ++i) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)digest[i];
  }
  return ss.str();
}
}