#include "logbrc.h"

#include <algorithm>
#include <stdexcept>
#include <unordered_set>

LogBRC::LogBRC(int domainSize) : domainSize(domainSize) {
  CryptoUtils::generateKey(key);
}

LogBRC::~LogBRC() { std::memset(key, 0, KEY_SIZE); }

std::vector<std::pair<int, int>> LogBRC::getDyadicRangesForValue(int value) {
  std::vector<std::pair<int, int>> ranges;
  int start = value;
  int len = 1;

  while (start >= 0 && start + len - 1 < domainSize) {
    ranges.emplace_back(start, start + len - 1);
    int nextLen = len * 2;
    start = (value / nextLen) * nextLen;
    len = nextLen;
  }
  return ranges;
}

std::vector<std::pair<int, int>> LogBRC::decomposeRange(int a, int b) {
  std::vector<std::pair<int, int>> ranges;
  int l = a;
  int r = b;

  while (l <= r) {
    int len = 1;
    while (l + len - 1 <= r && (l % len == 0) && l + len <= domainSize) {
      len *= 2;
    }
    len /= 2;
    ranges.emplace_back(l, l + len - 1);
    l += len;
  }
  return ranges;
}

void LogBRC::setup(const std::map<int, std::vector<int>>& database) {
  encryptedDatabase.clear();

  for (const auto& entry : database) {
    int w = entry.first;
    const std::vector<int>& tupleIDs = entry.second;

    std::vector<std::pair<int, int>> dyadicRanges = getDyadicRangesForValue(w);

    for (const auto& range : dyadicRanges) {
      std::string rangeStr =
          std::to_string(range.first) + "-" + std::to_string(range.second);
      unsigned char labelDigest[LABEL_SIZE];
      CryptoUtils::prf(key, KEY_SIZE, rangeStr, labelDigest);
      std::string label = CryptoUtils::digestToHex(labelDigest, LABEL_SIZE);

      for (int id : tupleIDs) {
        unsigned char iv[IV_SIZE];
        if (RAND_bytes(iv, IV_SIZE) != 1) {
          throw std::runtime_error("Failed to generate IV");
        }
        std::string encryptedID = CryptoUtils::encryptTupleID(key, id, iv);
        encryptedDatabase[label].push_back(encryptedID);
      }
    }
  }
}

std::vector<int> LogBRC::rangeSearch(int a, int b) {
  std::unordered_set<int> resultSet;
  auto dyadicRanges = decomposeRange(a, b);
  for (const auto& range : dyadicRanges) {
    std::string rangeStr =
        std::to_string(range.first) + "-" + std::to_string(range.second);
    unsigned char labelDigest[LABEL_SIZE];
    CryptoUtils::prf(key, KEY_SIZE, rangeStr, labelDigest);
    std::string label = CryptoUtils::digestToHex(labelDigest, LABEL_SIZE);
    auto it = encryptedDatabase.find(label);
    if (it != encryptedDatabase.end()) {
      unsigned char iv[IV_SIZE];
      for (const std::string& encryptedID : it->second) {
        int tupleID = CryptoUtils::decryptTupleID(key, encryptedID, iv);
        resultSet.insert(tupleID);
      }
    }
  }
  return std::vector<int>(resultSet.begin(), resultSet.end());
}

const std::map<std::string, std::vector<std::string>>&
LogBRC::getEncryptedDatabase() const {
  return encryptedDatabase;
}