#include "Catch2/include/catch.hpp"

#include "ust.hpp"

TEST_CASE("ConnectionTest", "[ConnectionTest]") {
  auto traceEntries = ust::generate();
  std::cout << traceEntries << std::endl;
}