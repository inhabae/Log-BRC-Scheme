#ifndef LOGBRC_H
#define LOGBRC_H

#include <map>
#include <string>
#include <vector>

#include "crypto.h"

class LogBRC {
 public:
  LogBRC(int domainSize);
  ~LogBRC();

  void setup(const std::map<int, std::vector<int>>& database);
  std::vector<int> rangeSearch(int a, int b);
  const std::map<std::string, std::vector<std::string>>& getEncryptedDatabase()
      const;

 private:
  unsigned char key[KEY_SIZE];
  std::map<std::string, std::vector<std::string>> encryptedDatabase;
  int domainSize;

  std::vector<std::pair<int, int>> decomposeRange(int a, int b);
  std::vector<std::pair<int, int>> getDyadicRangesForValue(int value);
};

#endif