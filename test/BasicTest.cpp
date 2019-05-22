#include "Catch2/include/catch.hpp"

#include "ust.hpp"

inline void checkBetween(int x, int low, int high) {
  REQUIRE(x >= low);
  REQUIRE(x <= high);
}

void f2();
void f();

void f() { f2(); }

void f2() {
  auto traceEntries = ust::generate();
  std::cout << traceEntries << std::endl;
  std::string fileName = std::string(__FILE__);
  fileName = std::string(ust::ustBasename(&fileName[0]));
  REQUIRE(traceEntries.entries[0].sourceFileName == __FILE__);
  checkBetween(traceEntries.entries[0].lineNumber, 16, 17);
  REQUIRE(traceEntries.entries[1].sourceFileName == __FILE__);
  REQUIRE(traceEntries.entries[1].lineNumber == 13);
  REQUIRE(traceEntries.entries[2].sourceFileName == __FILE__);
  REQUIRE(traceEntries.entries[2].lineNumber == 28);
}

TEST_CASE("ConnectionTest", "[ConnectionTest]") { f(); }
