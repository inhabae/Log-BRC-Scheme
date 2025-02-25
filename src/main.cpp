#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <chrono>
#include <iomanip>
#include <iostream>
#include <map>
#include <random>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

struct Tuple {
  int tid;
  int age;
};

// Computes a pseudorandom function using HMAC-SHA256
std::vector<unsigned char> PRF(const std::vector<unsigned char>& key,
                               const std::string& data) {
  unsigned char* result = nullptr;
  unsigned int len = 32;
  result = HMAC(EVP_sha256(), key.data(), key.size(),
                reinterpret_cast<const unsigned char*>(data.c_str()),
                data.size(), nullptr, &len);
  if (!result) {
    throw std::runtime_error("HMAC failed");
  }
  return std::vector<unsigned char>(result, result + len);
}

// Encrypts a 32-bit integer using AES-128 in CTR mode
std::vector<unsigned char> Encrypt(const std::vector<unsigned char>& key,
                                   int tid) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  std::vector<unsigned char> ciphertext(sizeof(tid));
  int len, plaintext_len = sizeof(tid);
  unsigned char iv[16] = {0};

  if (1 !=
      EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(), iv)) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_EncryptInit_ex failed");
  }
  if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len,
                             reinterpret_cast<unsigned char*>(&tid),
                             plaintext_len)) {
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

// Decrypts a 4-byte ciphertext into a 32-bit integer using AES-128 in CTR mode
int Decrypt(const std::vector<unsigned char>& key,
            const std::vector<unsigned char>& ciphertext) {
  EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
  if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");
  int tid, len, ciphertext_len = ciphertext.size();
  unsigned char iv[16] = {0};  // Zero IV, matching encryption

  if (1 !=
      EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), nullptr, key.data(), iv)) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptInit_ex failed");
  }
  if (1 != EVP_DecryptUpdate(ctx, reinterpret_cast<unsigned char*>(&tid), &len,
                             ciphertext.data(), ciphertext_len)) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptUpdate failed");
  }
  if (1 != EVP_DecryptFinal_ex(
               ctx, reinterpret_cast<unsigned char*>(&tid) + len, &len)) {
    EVP_CIPHER_CTX_free(ctx);
    throw std::runtime_error("EVP_DecryptFinal_ex failed");
  }
  EVP_CIPHER_CTX_free(ctx);
  return tid;
}

// LogBRC Setup
std::map<std::string,
         std::map<std::vector<unsigned char>, std::vector<unsigned char>>>
SetupLogBRC(const std::vector<Tuple>& database,
            const std::vector<unsigned char>& key, int domain_size) {
  std::map<std::string,
           std::map<std::vector<unsigned char>, std::vector<unsigned char>>>
      index;
  std::map<std::string, std::vector<int>> range_to_tids;
  int max_level = static_cast<int>(std::log2(domain_size));

  std::random_device rd;
  std::mt19937 gen(rd());

  // Build range-to-TID mapping
  for (const auto& tuple : database) {
    int v = tuple.age;
    for (int l = 0; l <= max_level; ++l) {
      int size = 1 << l;
      int start = (v / size) * size;
      int end = std::min(start + size - 1, domain_size - 1);
      std::string range = std::to_string(start) + "-" + std::to_string(end);
      range_to_tids[range].push_back(tuple.tid);
    }
  }

  // Encrypt per range
  for (const auto& [range, tids] : range_to_tids) {
    auto K1K2 = PRF(key, range);
    std::vector<unsigned char> K1(K1K2.begin(), K1K2.begin() + 16);
    std::vector<unsigned char> K2(K1K2.begin() + 16, K1K2.end());

    std::vector<int> permuted_tids(tids);
    std::shuffle(permuted_tids.begin(), permuted_tids.end(), gen);
    std::set<int> unique_tids(permuted_tids.begin(), permuted_tids.end());

    int counter = 0;
    for (int tid : unique_tids) {
      auto label = PRF(K1, std::to_string(counter));
      auto ciphertext = Encrypt(K2, tid);
      index[range][label] = ciphertext;
      counter++;
    }
    // std::cout << "Setup range " << range << ": " << counter << " entries\n";
  }
  return index;
}

std::vector<std::string> DecomposeRange(int low, int high, int domain_size) {
  std::vector<std::string> ranges;
  int current = low;

  while (current <= high) {
    int l = 0;
    while (current + (1 << (l + 1)) - 1 <= high &&
           (current % (1 << (l + 1))) == 0 &&
           (current + (1 << (l + 1)) - 1 < domain_size)) {
      ++l;
    }
    int size = 1 << l;
    int end = std::min(current + size - 1, high);
    ranges.push_back(std::to_string(current) + "-" + std::to_string(end));
    current = end + 1;
  }
  return ranges;
}

// LogBRC Search
std::vector<int> SearchLogBRC(
    const std::map<std::string, std::map<std::vector<unsigned char>,
                                         std::vector<unsigned char>>>& index,
    const std::vector<unsigned char>& key, int low, int high, int domain_size) {
  std::set<int> result_set;
  auto ranges = DecomposeRange(low, high, domain_size);
  // std::cout << "Search ranges: ";
  // for (const auto& r : ranges) std::cout << r << " ";
  // std::cout << "\n";

  for (const auto& range : ranges) {
    if (index.count(range) == 0) {
      // std::cout << "Range " << range << ": No entries\n";
      continue;
    }
    auto K1K2 = PRF(key, range);
    std::vector<unsigned char> K2(K1K2.begin() + 16,
                                  K1K2.end());  // Use next 16 bytes for AES-128
    const auto& sub_index = index.at(range);

    // std::cout << "Processing range " << range << " with " << sub_index.size()
    // << " entries\n";
    for (const auto& [label, ciphertext] : sub_index) {
      int tid = Decrypt(K2, ciphertext);
      result_set.insert(tid);
    }
  }

  std::vector<int> result(result_set.begin(), result_set.end());
  // std::cout << "Found " << result.size() << " results\n";
  return result;
}

int countRangeTuples(const std::vector<Tuple>& database, int low, int high) {
  int count = 0;
  std::cout << "Checking tuples in range [" << low << ", " << high << "]...\n";
  for (const auto& tuple : database) {
    if (tuple.age >= low && tuple.age <= high) {
      count++;
      // std::cout << "Found Tuple " << tuple.tid << " with age " << tuple.age
      // << "\n";
    }
  }
  std::cout << "Total tuples in range [" << low << ", " << high
            << "]: " << count << "\n";
  return count;
}

int main() {
  int n = 1;
  const int domain_size = 100;
  std::vector<Tuple> database;
  std::vector<unsigned char> key(16, 0x01);

  auto logBRCIndex = SetupLogBRC(database, key, domain_size);
  auto logBRCResults = SearchLogBRC(logBRCIndex, key, 0, 2, domain_size);

  auto start = std::chrono::high_resolution_clock::now();
  auto end = std::chrono::high_resolution_clock::now();

  for (int i = 20; i <= 20; i++) {
    n = i << i;
    for (int i = 0; i < n; ++i) {
      database.push_back({i, rand() % domain_size});
    }

    start = std::chrono::high_resolution_clock::now();
    logBRCIndex = SetupLogBRC(database, key, domain_size);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "LogBRC Setup Time at n 2^" << i << ": "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                       start)
                     .count()
              << " ms\n";

    start = std::chrono::high_resolution_clock::now();
    logBRCResults = SearchLogBRC(logBRCIndex, key, 0, 2, domain_size);
    end = std::chrono::high_resolution_clock::now();
    std::cout << "LogBRC Range [0, 2] Time: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                       start)
                     .count()
              << " ms, Size: " << logBRCResults.size() << "\n";
  }
  return 0;
}