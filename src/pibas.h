#ifndef PIBAS_H
#define PIBAS_H

#include <map>
#include <string>
#include <vector>

#include "crypto.h"

class PiBas {
 public:
  PiBas();
  ~PiBas();

  void setup(const std::map<int, std::vector<int>>& database);
  std::vector<int> search(int w);
  std::vector<int> rangeSearch(int a, int b);
  const std::map<std::string, std::string>& getEncryptedDatabase() const;

 private:
  unsigned char key[KEY_SIZE];
  std::map<std::string, std::string> encryptedDatabase;
};

#endif