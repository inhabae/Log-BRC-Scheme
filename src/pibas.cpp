#include "pibas.h"

#include <stdexcept>

PiBas::PiBas() { CryptoUtils::generateKey(key); }

PiBas::~PiBas() { std::memset(key, 0, KEY_SIZE); }

void PiBas::setup(const std::map<int, std::vector<int>>& database) {
  encryptedDatabase.clear();

  for (const auto& entry : database) {
    int w = entry.first;
    const std::vector<int>& tupleIDs = entry.second;

    std::string w_str = std::to_string(w);
    std::string k1_data = "1" + w_str;
    std::string k2_data = "2" + w_str;
    unsigned char k1[KEY_SIZE];
    unsigned char k2[KEY_SIZE];
    CryptoUtils::prf(key, KEY_SIZE, k1_data, k1);
    CryptoUtils::prf(key, KEY_SIZE, k2_data, k2);

    int c = 0;
    for (int id : tupleIDs) {
      std::string c_str = std::to_string(c);
      unsigned char label_digest[KEY_SIZE];
      CryptoUtils::prf(k1, KEY_SIZE, c_str, label_digest);
      std::string label = CryptoUtils::digestToHex(label_digest, KEY_SIZE);

      unsigned char iv[IV_SIZE];
      if (RAND_bytes(iv, IV_SIZE) != 1) {
        throw std::runtime_error("Failed to generate IV");
      }

      std::string encryptedID = CryptoUtils::encryptTupleID(k2, id, iv);
      encryptedDatabase[label] = encryptedID;
      ++c;
    }
  }
}

std::vector<int> PiBas::search(int w) {
  std::vector<int> result;

  std::string w_str = std::to_string(w);
  std::string k1_data = "1" + w_str;
  std::string k2_data = "2" + w_str;
  unsigned char k1[KEY_SIZE];
  unsigned char k2[KEY_SIZE];
  CryptoUtils::prf(key, KEY_SIZE, k1_data, k1);
  CryptoUtils::prf(key, KEY_SIZE, k2_data, k2);

  int c = 0;
  unsigned char iv[IV_SIZE];
  while (true) {
    std::string c_str = std::to_string(c);
    unsigned char label_digest[KEY_SIZE];
    CryptoUtils::prf(k1, KEY_SIZE, c_str, label_digest);
    std::string label = CryptoUtils::digestToHex(label_digest, KEY_SIZE);

    auto it = encryptedDatabase.find(label);
    if (it == encryptedDatabase.end()) {
      break;
    }

    int tupleID = CryptoUtils::decryptTupleID(k2, it->second, iv);
    result.push_back(tupleID);
    ++c;
  }

  return result;
}

std::vector<int> PiBas::rangeSearch(int a, int b) {
  std::vector<int> result;
  for (int w = a; w <= b; ++w) {
    std::vector<int> ids = search(w);
    result.insert(result.end(), ids.begin(), ids.end());
  }
  std::sort(result.begin(), result.end());
  result.erase(std::unique(result.begin(), result.end()), result.end());
  return result;
}

const std::map<std::string, std::string>& PiBas::getEncryptedDatabase() const {
  return encryptedDatabase;
}