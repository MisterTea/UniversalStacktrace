#pragma once

#if (defined(__MINGW32__) || defined(__MINGW64__))
#define __MINGW__
#undef _MSC_VER
#endif

#ifdef _MSC_VER
#include <DbgHelp.h>
#include <windows.h>
#else
#ifdef __MINGW__
#include "backtrace.h"
#else
#include <cxxabi.h>
#include <errno.h>
#include <execinfo.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zconf.h>
#endif
#endif

#include <array>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
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

#ifndef _MSC_VER
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
#endif

#ifdef __MINGW__
int bt_callback(void* data, uintptr_t pc, const char* filename, int lineno,
                const char* function);

inline void libbacktrace_error_callback(void* data, const char* msg, int errnum) {
  if (msg) {
    std::cout << "GOT ERROR: " << std::string(msg) << " " << errnum << std::endl;
  } else {
    std::cout << "GOT ERROR: " << errnum << std::endl;
  }
}
#endif

static const unsigned int kMaxStack = 64;
static const unsigned int kStackStart = 0;
class StackTraceEntry {
 public:
  StackTraceEntry(std::size_t index, const std::string& _fileName,
                  const std::string& demang, const std::string& addr)
      : m_index(index),
        fileName(_fileName),
        m_demangled(demang),
        m_addr(addr) {}

  std::size_t m_index;
  std::string fileName;
  std::string m_demangled;
  std::string m_addr;
  friend std::ostream& operator<<(std::ostream& ss, const StackTraceEntry& si);

 private:
  StackTraceEntry(void);
};

inline std::ostream& operator<<(std::ostream& ss, const StackTraceEntry& si) {
  ss << "[" << si.m_index << "] " << si.m_addr << " "
     << (si.m_demangled.empty() ? "" : "") << si.m_demangled;
  return ss;
}

class StackTrace {
 public:
  StackTrace(const std::vector<StackTraceEntry>& _entries) : entries(_entries) {
#ifdef _MSC_VER
    HANDLE process = GetCurrentProcess();
    HANDLE thread = GetCurrentThread();

    CONTEXT context;
    memset(&context, 0, sizeof(CONTEXT));
    context.ContextFlags = CONTEXT_FULL;
    RtlCaptureContext(&context);

    SymSetOptions(SYMOPT_LOAD_LINES);
    SymInitialize(process, NULL, TRUE);

    DWORD image;
    STACKFRAME64 stackframe;
    ZeroMemory(&stackframe, sizeof(STACKFRAME64));

#ifdef _M_IX86
    image = IMAGE_FILE_MACHINE_I386;
    stackframe.AddrPC.Offset = context.Eip;
    stackframe.AddrPC.Mode = AddrModeFlat;
    stackframe.AddrFrame.Offset = context.Ebp;
    stackframe.AddrFrame.Mode = AddrModeFlat;
    stackframe.AddrStack.Offset = context.Esp;
    stackframe.AddrStack.Mode = AddrModeFlat;
#elif _M_X64
    image = IMAGE_FILE_MACHINE_AMD64;
    stackframe.AddrPC.Offset = context.Rip;
    stackframe.AddrPC.Mode = AddrModeFlat;
    stackframe.AddrFrame.Offset = context.Rsp;
    stackframe.AddrFrame.Mode = AddrModeFlat;
    stackframe.AddrStack.Offset = context.Rsp;
    stackframe.AddrStack.Mode = AddrModeFlat;
#elif _M_IA64
    image = IMAGE_FILE_MACHINE_IA64;
    stackframe.AddrPC.Offset = context.StIIP;
    stackframe.AddrPC.Mode = AddrModeFlat;
    stackframe.AddrFrame.Offset = context.IntSp;
    stackframe.AddrFrame.Mode = AddrModeFlat;
    stackframe.AddrBStore.Offset = context.RsBSP;
    stackframe.AddrBStore.Mode = AddrModeFlat;
    stackframe.AddrStack.Offset = context.IntSp;
    stackframe.AddrStack.Mode = AddrModeFlat;
#endif

    for (size_t i = 0; i < 25; i++) {
      BOOL result =
          StackWalk64(image, process, thread, &stackframe, &context, NULL,
                      SymFunctionTableAccess64, SymGetModuleBase64, NULL);

      if (!result) {
        break;
      }

      if (stackframe.AddrPC.Offset == stackframe.AddrReturn.Offset) break;

      const int cnBufferSize = 4096;
      unsigned char byBuffer[sizeof(IMAGEHLP_SYMBOL64) + cnBufferSize];
      IMAGEHLP_SYMBOL64* pSymbol = (IMAGEHLP_SYMBOL64*)byBuffer;
      memset(pSymbol, 0, sizeof(IMAGEHLP_SYMBOL64) + cnBufferSize);
      pSymbol->SizeOfStruct = sizeof(IMAGEHLP_SYMBOL64);
      pSymbol->MaxNameLength = cnBufferSize;

      DWORD64 displacement = 0;
      if (SymGetSymFromAddr64(process, stackframe.AddrPC.Offset, &displacement,
                              pSymbol)) {
        printf("[%lld] %s\n", i, pSymbol->Name);
      } else {
        printf("[%lld] ???\n", i);
      }

      DWORD displacement32 = 0;
      IMAGEHLP_LINE64 theLine;
      memset(&theLine, 0, sizeof(theLine));
      theLine.SizeOfStruct = sizeof(theLine);
      if (SymGetLineFromAddr64(process, stackframe.AddrPC.Offset,
                               &displacement32, &theLine)) {
        printf("%s:%ld\n", theLine.FileName, theLine.LineNumber);
      } else {
        printf("???\n");
      }
    }

    SymCleanup(process);
    return;
#endif

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
    return;
#endif

#ifdef __MINGW__
    return;
#endif

    std::map<std::string, std::list<std::string> > fileAddresses;
    std::map<std::string, std::list<std::string> > fileData;
    for (const auto& it : entries) {
      if (it.fileName.length()) {
        if (fileAddresses.find(it.fileName) == fileAddresses.end()) {
          fileAddresses[it.fileName] = {};
        }
        fileAddresses.at(it.fileName).push_back(it.m_addr);
      }
    }
    for (const auto& it : fileAddresses) {
      std::string fileName = it.first;
      std::ostringstream ss;
      ss << "addr2line -C -f -p -e " << fileName << " ";
      for (const auto& it2 : it.second) {
        ss << it2 << " ";
      }
      auto outputLines = split(SystemToStr(ss.str().c_str()), '\n');
      fileData[fileName] =
          std::list<std::string>(outputLines.begin(), outputLines.end());
    }
    for (auto& it : entries) {
      if (it.fileName.length()) {
        std::string outputLine = fileData.at(it.fileName).front();
        fileData.at(it.fileName).pop_front();
        it.m_demangled = outputLine;
      }
    }
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
#ifdef _MSC_VER
  return StackTrace(stackTrace);
#endif

#ifdef __MINGW__
  static ::backtrace_state* state =
      ::backtrace_create_state("E:\\GitHub\\UniversalStacktrace\\build\\ust-test.exe", 0, libbacktrace_error_callback, NULL);
  ::backtrace_full(state, 0, bt_callback, libbacktrace_error_callback, (void*)&stackTrace);
  return StackTrace(stackTrace);
#endif

#ifndef __MINGW__
#ifdef __APPLE__
  // TODO: Handle relocatable code
#else
  std::map<std::string, uint64_t> baseAddresses;
  std::string line;
  std::string procMapFileName =
      std::string("/proc/") + std::to_string(getpid()) + std::string("/maps");
  std::ifstream infile(procMapFileName.c_str());
  while (std::getline(infile, line)) {
    std::istringstream iss(line);
    std::string addressRange;
    std::string perms;
    std::string offset;
    std::string device;
    std::string inode;
    std::string path;
    std::cout << "PROC LINE: " << line << std::endl;

    if (!(iss >> addressRange >> perms >> offset >> device >> inode >> path)) {
      break;
    }  // error
    uint64_t baseAddress = stoull(split(addressRange, '-')[0], NULL, 16);
    if (baseAddresses.find(path) == baseAddresses.end() ||
        baseAddresses[path] > baseAddress) {
      baseAddresses[path] = baseAddress;
    }
  }
#endif
  void* stack[kMaxStack];
  unsigned int size = backtrace(stack, kMaxStack);
  char** strings = backtrace_symbols(stack, size);
  if (size > kStackStart) {  // Skip StackTrace c'tor and generateNew
    for (std::size_t i = kStackStart; i < size; ++i) {
      std::string fileName;
      std::string mangName;
      std::string hex;
      std::string addr;

      const std::string line(strings[i]);
      std::cout << "LINE: " << line << std::endl;
#ifdef __APPLE__
      // Example: ust-test                            0x000000010001e883
      // _ZNK5Catch21TestInvokerAsFunction6invokeEv + 19
      auto p = line.find("0x");
      if (p != std::string::npos) {
        addr = line.substr(p);
        auto spaceLoc = addr.find(" ");
        mangName = addr.substr(spaceLoc + 1);
        mangName = mangName.substr(0, mangName.find(" +"));
        addr = addr.substr(0, spaceLoc);
      }
#else
      // Example: ./ust-test(_ZNK5Catch21TestInvokerAsFunction6invokeEv+0x16)
      // [0x55f1278af96e]
      auto parenStart = line.find("(");
      auto parenEnd = line.find(")");
      fileName = line.substr(0, parenStart);
      // Convert filename to canonical path
      char buf[PATH_MAX];
      ::realpath(fileName.c_str(), buf);
      std::cout << "FILENAME MAPPED FROM " << fileName << " TO " << buf
                << std::endl;
      fileName = std::string(buf);
      mangName = line.substr(parenStart + 1, parenEnd - (parenStart + 1));
      // Strip off the offset from the name
      mangName = mangName.substr(0, mangName.find("+"));
      auto bracketStart = line.find("[");
      auto bracketEnd = line.find("]");
      addr = line.substr(bracketStart + 1, bracketEnd - (bracketStart + 1));
      if (baseAddresses.find(fileName) != baseAddresses.end()) {
        auto addrHex = (std::stoull(addr, NULL, 16) - baseAddresses[fileName]);
        std::ostringstream ss;
        ss << "0x" << std::hex << addrHex;
        std::cout << "ADDR MAPPED FROM " << addr << " -> " << ss.str()
                  << std::endl;
        addr = ss.str();
      }
#endif
      // Perform demangling if parsed properly
      if (!mangName.empty()) {
        int status = 0;
        std::cout << "DEMANGLE" << mangName << std::endl;
        char* demangName = abi::__cxa_demangle(mangName.data(), 0, 0, &status);
        // if demangling is successful, output the demangled function name
        if (status == 0) {
          // Success (see
          // http://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html)
          StackTraceEntry entry(i - kStackStart, fileName, demangName, addr);
          stackTrace.push_back(entry);
        } else {
          std::cout << "DEMANGLE FAILED" << std::endl;
          // Not successful - we will use mangled name
          StackTraceEntry entry(i - kStackStart, fileName, mangName, addr);
          stackTrace.push_back(entry);
        }
        free(demangName);
      } else {
        StackTraceEntry entry(i - kStackStart, fileName, mangName, addr);
        stackTrace.push_back(entry);
      }
    }
  }
  free(strings);
#endif
  return StackTrace(stackTrace);
}

#ifdef __MINGW__
int bt_callback(void* data, uintptr_t pc, const char* fileName, int lineno,
                const char* function) {
                  std::cout << "GOT CALLBACK: " << pc << " " << (fileName?std::string(fileName):"NULL") << " " << lineno << " " << (function?std::string(function):"NULL") << std::endl;
  std::vector<StackTraceEntry>* stackTrace =
      (std::vector<StackTraceEntry>*)data;
  StackTraceEntry entry(
      pc, fileName?std::string(fileName):"NULL",
      (function?std::string(function):"NULL") + std::string(":") + std::to_string(lineno),
      std::to_string(pc));
  stackTrace->push_back(entry);
  return 0;
}
#endif
}  // namespace ust
