#pragma once

#if !defined(__GNUC__)
#error This is only designed for GNU-basbed compilers (gcc, clang, etc.).
#endif

#if (defined(__MINGW32__) || defined(__MINGW64__))
#define __MINGW__
#endif

#ifdef __MINGW__
#else
#include <cxxabi.h>
#include <errno.h>
#include <execinfo.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zconf.h>
#endif

#include <array>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace ust {
template <typename Out>
inline void split(const std::string& s, char delim, Out result) {
  std::stringstream ss;
  ss.str(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    *(result++) = item;
  }
}

inline std::vector<std::string> split(const std::string& s, char delim) {
  std::vector<std::string> elems;
  split(s, delim, std::back_inserter(elems));
  return elems;
}

inline std::string SystemToStr(const char* cmd) {
  std::array<char, 128> buffer;
  std::string result;
  std::shared_ptr<FILE> pipe(popen(cmd, "r"), pclose);
  if (!pipe) throw std::runtime_error("popen() failed!");
  while (!feof(pipe.get())) {
    if (fgets(buffer.data(), 128, pipe.get()) != nullptr)
      result += buffer.data();
  }
  return result;
}

static const unsigned int kMaxStack = 64;
static const unsigned int kStackStart = 0;
class StackTraceEntry {
 public:
  StackTraceEntry(std::size_t index, const std::string& demang,
                  const std::string& hex, const std::string& addr)
      : m_index(index), m_demangled(demang), m_hex(hex), m_addr(addr) {}

  StackTraceEntry(std::size_t index, const std::string& loc)
      : m_index(index), m_location(loc) {}
  std::size_t m_index;
  std::string m_location;
  std::string m_demangled;
  std::string m_hex;
  std::string m_addr;
  friend std::ostream& operator<<(std::ostream& ss, const StackTraceEntry& si);

 private:
  StackTraceEntry(void);
};

inline std::ostream& operator<<(std::ostream& ss, const StackTraceEntry& si) {
  ss << "[" << si.m_index << "] " << si.m_location
     << (si.m_hex.empty() ? "" : "+") << si.m_hex << " " << si.m_addr << " "
     << (si.m_demangled.empty() ? "" : "") << si.m_demangled;
  return ss;
}

std::string getexepath() {
  char result[PATH_MAX];
  ssize_t count = readlink("/proc/self/exe", result, PATH_MAX);
  return std::string(result, (count > 0) ? count : 0);
}

class StackTrace {
 public:
  StackTrace(const std::vector<StackTraceEntry>& _entries) : entries(_entries) {
#ifdef __APPLE__
    std::ostringstream ss;
    ss << "atos -p " << std::to_string(getpid()) << " ";
    for (const auto& it : entries) {
      ss << it.m_addr << " ";
    }
    auto atosLines = split(SystemToStr(ss.str().c_str()), '\n');
    for (int a = 0; a < int(entries.size()); a++) {
      entries[a].m_demangled = atosLines[a];
    }
#endif
  }
  friend std::ostream& operator<<(std::ostream& ss, const StackTrace& si);

 protected:
  std::vector<StackTraceEntry> entries;
};

inline std::ostream& operator<<(std::ostream& ss, const StackTrace& si) {
  for (const auto& it : si.entries) {
    ss << it << "\n";
  }
  return ss;
}

StackTrace generate() {
  std::vector<StackTraceEntry> stackTrace;
#ifdef __MINGW__
#else
  void* stack[kMaxStack];
  unsigned int size = backtrace(stack, kMaxStack);
  char** strings = backtrace_symbols(stack, size);
  if (size > kStackStart) {  // Skip StackTrace c'tor and generateNew
    for (std::size_t i = kStackStart; i < size; ++i) {
      std::string mangName;
      std::string hex;
      std::string addr;

      // entry: 2   crash.cpp.bin                       0x0000000101552be5
      // _ZN2el4base5debug10StackTraceC1Ev + 21
      const std::string line(strings[i]);
      std::cout << "LINE: " << line << std::endl;
      auto p = line.find("0x");
      if (p != std::string::npos) {
        addr = line.substr(p);
        auto spaceLoc = addr.find(" ");
        mangName = addr.substr(spaceLoc + 1);
        mangName = mangName.substr(0, mangName.find(" +"));
        addr = addr.substr(0, spaceLoc);
      }
      // Perform demangling if parsed properly
      if (!mangName.empty()) {
        int status = 0;
        std::cout << "DEMANGLE" << mangName << std::endl;
        char* demangName = abi::__cxa_demangle(mangName.data(), 0, 0, &status);
        // if demangling is successful, output the demangled function name
        if (status == 0) {
          // Success (see
          // http://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html)
          StackTraceEntry entry(i - kStackStart, demangName, hex, addr);
          stackTrace.push_back(entry);
        } else {
          std::cout << "DEMANGLE FAILED" << std::endl;
          // Not successful - we will use mangled name
          StackTraceEntry entry(i - kStackStart, mangName, hex, addr);
          stackTrace.push_back(entry);
        }
        free(demangName);
      } else {
        StackTraceEntry entry(i - kStackStart, line);
        stackTrace.push_back(entry);
      }
    }
  }
  free(strings);
#endif
  return StackTrace(stackTrace);
}
}  // namespace ust
