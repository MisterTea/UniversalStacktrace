cmake_minimum_required (VERSION 3.0.2)
project (UniversalStackTrace VERSION 0.0.1)

# Enable C++-17
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++17")

# Enable debug info
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -ggdb3")
SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -ggdb3")

IF(APPLE)
# Turn off address randomizing to get debug prints
SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -fno-pie")
ELSEIF(UNIX)
# Enable dynamic relocation
SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -rdynamic")
ENDIF()

include_directories(
  external
  ust
  )

IF(MINGW)
SET(
BACKTRACE_FILES

external/libbacktrace_mingw/atomic.c
external/libbacktrace_mingw/dwarf.c
external/libbacktrace_mingw/fileline.c
external/libbacktrace_mingw/posix.c
external/libbacktrace_mingw/print.c
external/libbacktrace_mingw/sort.c
external/libbacktrace_mingw/state.c
external/libbacktrace_mingw/backtrace.c
external/libbacktrace_mingw/simple.c
external/libbacktrace_mingw/pecoff.c
external/libbacktrace_mingw/read.c
external/libbacktrace_mingw/alloc.c
)
include_directories(
  external/libbacktrace_mingw
  )
ELSE()
SET(BACKTRACE_FILES)
ENDIF()

add_executable(
  ust-test

  ${BACKTRACE_FILES}

  test/Main.cpp

  test/BasicTest.cpp
  )
target_link_libraries(
  ust-test

  ole32
  Dbghelp
)
add_test(
  ust-test
  ust-test
  )
