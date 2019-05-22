#pragma once

#if defined(__MINGW32__) || defined(__MINGW64__)
#define __MINGW__
#undef _MSC_VER
#endif

#ifdef _WIN32
#include <windows.h>

#include <DbgHelp.h>
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

#include <array>
#include <fstream>
#include <iostream>
#include <list>
#include <map>
#include <regex>
#include <sstream>
#include <string>
#include <vector>

namespace ust {
template <typename Out>
inline void split(const std::string &s, char delim, Out result) {
  std::stringstream ss;
  ss.str(s);
  std::string item;
  while (std::getline(ss, item, delim)) {
    *(result++) = item;
  }
}

inline std::vector<std::string> split(const std::string &s, char delim) {
  std::vector<std::string> elems;
  split(s, delim, std::back_inserter(elems));
  return elems;
}

#ifndef _MSC_VER
// Needed for calling addr2line / atos
inline std::string SystemToStr(const char *cmd) {
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

static const unsigned int kMaxStack = 64;
class StackTraceEntry {
 public:
  StackTraceEntry(int _stackIndex, const std::string &_address,
                  const std::string &_functionName,
                  const std::string &_sourceFileName, int _lineNumber)
      : stackIndex(_stackIndex),
        address(_address),
        functionName(_functionName),
        sourceFileName(_sourceFileName),
        lineNumber(_lineNumber) {}

  int stackIndex;
  std::string address;
  std::string functionName;
  std::string sourceFileName;
  int lineNumber;

  friend std::ostream &operator<<(std::ostream &ss, const StackTraceEntry &si);

 private:
  StackTraceEntry(void);
};

inline std::ostream &operator<<(std::ostream &ss, const StackTraceEntry &si) {
  ss << "[" << si.stackIndex << "] " << si.address;
  if (!si.functionName.empty()) {
    ss << " " << si.functionName;
  }
  if (si.lineNumber > 0) {
    ss << " (" << si.sourceFileName << ":" << si.lineNumber << ")";
  }
  return ss;
}

class StackTrace {
 public:
  StackTrace(const std::vector<StackTraceEntry> &_entries) : entries(_entries) {
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
      IMAGEHLP_SYMBOL64 *pSymbol = (IMAGEHLP_SYMBOL64 *)byBuffer;
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
    return;
#endif
  }
  friend std::ostream &operator<<(std::ostream &ss, const StackTrace &si);

 protected:
  std::vector<StackTraceEntry> entries;
};

inline std::ostream &operator<<(std::ostream &ss, const StackTrace &si) {
  for (const auto &it : si.entries) {
    ss << it << "\n";
  }
  return ss;
}

StackTrace generate() {
  std::vector<StackTraceEntry> stackTrace;
#ifdef _MSC_VER
  return StackTrace(stackTrace);
#endif

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

#ifdef __MINGW__
#define BACKTRACE_MAX_FRAME_NUMBER 128
  void *stack[BACKTRACE_MAX_FRAME_NUMBER];
  unsigned short frames;

  frames = CaptureStackBackTrace(0, BACKTRACE_MAX_FRAME_NUMBER, stack, NULL);

  // For mingw, assume the filename is the executable
  std::string fileName(4096, '\0');
  auto fileNameSize = GetModuleFileNameA(0, &fileName[0], fileName.size());
  if (fileNameSize == 0 || fileNameSize == (ssize_t)fileName.size()) {
    /* Error, possibly not enough space. */
    fileName = "";
  } else {
    fileName = fileName.substr(0, fileNameSize);
  }

  for (unsigned short i = 0; i < frames; i++) {
    std::string addr;
    std::ostringstream ss;
    ss << "0x" << std::hex << uint64_t(stack[i]);
    addr = ss.str();
    StackTraceEntry entry(i, fileName, "", addr);
    stackTrace.push_back(entry);
  }
  return StackTrace(stackTrace);

#endif

  void *stack[kMaxStack];
  unsigned int size = backtrace(stack, kMaxStack);

  std::string addresses[kMaxStack];
  std::string sourceFiles[kMaxStack];
  int lineNumbers[kMaxStack];
  for (int a = 0; a < kMaxStack; a++) {
    lineNumbers[a] = -1;
  }

#ifdef __APPLE__
  for (int a = 0; a < size; a++) {
    std::ostringstream ss;
    ss << "0x" << std::hex << uint64_t(stack[a]);
    addresses[a] = ss.str();
  }
  std::ostringstream ss;
  ss << "atos -p " << std::to_string(getpid()) << " ";
  for (int a = 0; a < size; a++) {
    ss << "0x" << std::hex << uint64_t(stack[a]) << " ";
  }
  auto atosLines = split(SystemToStr(ss.str().c_str()), '\n');
  std::regex fileLineRegex("\\(([^\\(]+):([0-9]+)\\)$");
  for (int a = 0; a < size; a++) {
    std::cout << "ATOS LINE: " << atosLines[a] << std::endl;
    // Find the filename and line number
    std::smatch matches;
    if (regex_search(atosLines[a], matches, fileLineRegex)) {
      std::cout << "MATCHES: " << matches[1] << std::endl;
      sourceFiles[a] = matches[1];
      std::cout << "MATCHES: " << matches[2] << std::endl;
      lineNumbers[a] = std::stoi(matches[2]);
      std::cout << "MATCHES: " << matches.size() << std::endl;
    }
  }
#elif defined(_WIN32)
#else
  // Unix
  std::map<std::string, std::list<std::string> > fileAddresses;
  std::map<std::string, std::list<std::string> > fileData;
  for (const auto &it : entries) {
    if (it.fileName.length()) {
      if (fileAddresses.find(it.fileName) == fileAddresses.end()) {
        fileAddresses[it.fileName] = {};
      }
      fileAddresses.at(it.fileName).push_back(it.address);
    }
  }
  for (const auto &it : fileAddresses) {
    std::string fileName = it.first;
    std::ostringstream ss;
    ss << "addr2line -C -f -p -e " << fileName << " ";
    for (const auto &it2 : it.second) {
      ss << it2 << " ";
    }
    auto outputLines = split(SystemToStr(ss.str().c_str()), '\n');
    fileData[fileName] =
        std::list<std::string>(outputLines.begin(), outputLines.end());
  }
  for (auto &it : entries) {
    if (it.fileName.length()) {
      std::string outputLine = fileData.at(it.fileName).front();
      fileData.at(it.fileName).pop_front();
      it.functionName = outputLine;
    }
  }
#endif

  char **strings = backtrace_symbols(stack, size);
  for (int i = 0; i < size; ++i) {
    std::string addr;
    std::string fileName;
    std::string functionName;

    const std::string line(strings[i]);
    std::cout << "BACKTRACE SYMBOLS: " << strings[i] << std::endl;
#ifdef __APPLE__
    // Example: ust-test                            0x000000010001e883
    // _ZNK5Catch21TestInvokerAsFunction6invokeEv + 19
    auto p = line.find("0x");
    if (p != std::string::npos) {
      addr = line.substr(p);
      auto spaceLoc = addr.find(" ");
      functionName = addr.substr(spaceLoc + 1);
      functionName = functionName.substr(0, functionName.find(" +"));
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
    fileName = std::string(buf);
    functionName = line.substr(parenStart + 1, parenEnd - (parenStart + 1));
    // Strip off the offset from the name
    functionName = functionName.substr(0, functionName.find("+"));
    auto bracketStart = line.find("[");
    auto bracketEnd = line.find("]");
    addr = line.substr(bracketStart + 1, bracketEnd - (bracketStart + 1));
    if (baseAddresses.find(fileName) != baseAddresses.end()) {
      auto addrHex = (std::stoull(addr, NULL, 16) - baseAddresses[fileName]);
      std::ostringstream ss;
      ss << "0x" << std::hex << addrHex;
      addr = ss.str();
    }
#endif
    // Perform demangling if parsed properly
    if (!functionName.empty()) {
      int status = 0;
      std::cout << "Mangled name: " << functionName << std::endl;
      auto demangledFunctionName =
          abi::__cxa_demangle(functionName.data(), 0, 0, &status);
      // if demangling is successful, output the demangled function name
      if (status == 0) {
        std::cout << "success: " << functionName << " -> "
                  << demangledFunctionName << std::endl;
        // Success (see
        // http://gcc.gnu.org/onlinedocs/libstdc++/libstdc++-html-USERS-4.3/a01696.html)
        functionName = std::string(demangledFunctionName);
      }
      free(demangledFunctionName);
    }
    StackTraceEntry entry(i, addresses[i], functionName, sourceFiles[i],
                          lineNumbers[i]);
    stackTrace.push_back(entry);
  }
  free(strings);
  return StackTrace(stackTrace);
}  // namespace ust
}  // namespace ust
