#include <chrono>
#include <cmath>
#include <iostream>
#include <random>
#include <vector>

#include "logbrc.h"
#include "pibas.h"

const int MIN_AGE = 1;
const int MAX_AGE = 100;
const int DOMAIN_SIZE = MAX_AGE - MIN_AGE + 1;

std::map<int, std::vector<int>> generateDatabase(int numTuples, int minAge,
                                                 int maxAge) {
  std::map<int, std::vector<int>> database;
  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<> ageDist(minAge, maxAge);

  for (int tupleID = 0; tupleID < numTuples; ++tupleID) {
    int age = ageDist(gen);
    database[age].push_back(tupleID);
  }
  return database;
}

void testInputSize() {
  std::cout << "\n=== Test 1: Input Size (n = 2^1 to 2^20) ===\n";
  std::cout << "n\tLogBRC Setup (ms)\tLogBRC Search (ms)\tPiBas Setup "
               "(ms)\tPiBas Search (ms)\n";

  for (int exp = 1; exp <= 20; ++exp) {
    int n = 1 << exp;
    auto database = generateDatabase(n, MIN_AGE, MAX_AGE);

    LogBRC logBRC(DOMAIN_SIZE);
    auto start = std::chrono::high_resolution_clock::now();
    logBRC.setup(database);
    auto end = std::chrono::high_resolution_clock::now();
    double logBRCSetupTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();

    start = std::chrono::high_resolution_clock::now();
    logBRC.rangeSearch(25, 50);
    end = std::chrono::high_resolution_clock::now();
    double logBRCSearchTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();

    PiBas piBas;
    start = std::chrono::high_resolution_clock::now();
    piBas.setup(database);
    end = std::chrono::high_resolution_clock::now();
    double piBasSetupTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();

    start = std::chrono::high_resolution_clock::now();
    piBas.rangeSearch(25, 50);
    end = std::chrono::high_resolution_clock::now();
    double piBasSearchTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();

    std::cout << n << "\t" << logBRCSetupTime << "\t\t\t" << logBRCSearchTime
              << "\t\t\t" << piBasSetupTime << "\t\t\t" << piBasSearchTime
              << "\n";
  }
}

void testRangeSize() {
  std::cout << "\n=== Test 2: Range Size (1 to 100) at n = 2^20 ===\n";
  int n = 1 << 20;
  auto database = generateDatabase(n, MIN_AGE, MAX_AGE);

  LogBRC logBRC(DOMAIN_SIZE);
  auto start = std::chrono::high_resolution_clock::now();
  logBRC.setup(database);
  auto end = std::chrono::high_resolution_clock::now();
  std::cout << "LogBRC Setup took: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     start)
                   .count()
            << " ms\n";

  PiBas piBas;
  start = std::chrono::high_resolution_clock::now();
  piBas.setup(database);
  end = std::chrono::high_resolution_clock::now();
  std::cout << "PiBas Setup took: "
            << std::chrono::duration_cast<std::chrono::milliseconds>(end -
                                                                     start)
                   .count()
            << " ms\n";

  std::cout << "Range Size\tLogBRC Search (ms)\tPiBas Search (ms)\n";
  for (int rangeSize = 1; rangeSize <= 99; ++rangeSize) {
    int a = MIN_AGE;
    int b = a + rangeSize - 1;
    if (b > MAX_AGE) b = MAX_AGE;

    start = std::chrono::high_resolution_clock::now();
    logBRC.rangeSearch(a, b);
    end = std::chrono::high_resolution_clock::now();
    double logBRCSearchTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();

    start = std::chrono::high_resolution_clock::now();
    piBas.rangeSearch(a, b);
    end = std::chrono::high_resolution_clock::now();
    double piBasSearchTime =
        std::chrono::duration_cast<std::chrono::milliseconds>(end - start)
            .count();

    std::cout << rangeSize << "\t\t" << logBRCSearchTime << "\t\t\t"
              << piBasSearchTime << "\n";
  }
}

int main() {
  try {
    testInputSize();
    testRangeSize();
  } catch (const std::exception& e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }
  return 0;
}