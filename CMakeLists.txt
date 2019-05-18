cmake_minimum_required (VERSION 3.0.2)
project (WeGoAll VERSION 0.0.1)

# Enable C++-17
if(UNIX)
	SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++17")
endif()

# Enable debug info
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g")

IF(APPLE)
# Turn off address randomizing to get debug prints
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-pie")
ENDIF()

include_directories(
  external
  ust
  )

add_executable(
  ust-test

  test/Main.cpp

  test/BasicTest.cpp
  )
add_test(
  ust-test
  ust-test
  )
