#ifndef CRYPTO_H
#define CRYPTO_H

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <string>

const int KEY_SIZE = 32;
const int IV_SIZE = 16;
const int LABEL_SIZE = 32;

namespace CryptoUtils {
void prf(const unsigned char* key, int key_len, const std::string& data,
         unsigned char* output);

std::string encryptTupleID(const unsigned char* key, int tupleID,
                           unsigned char* iv);

int decryptTupleID(const unsigned char* key, const std::string& encryptedData,
                   unsigned char* iv);

void generateKey(unsigned char* key);

std::string digestToHex(const unsigned char* digest, int len);
}

#endif