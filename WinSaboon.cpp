#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <chrono>
#include <ctime>
#include <cassert>
#include <sstream>
#include <array>
#include <algorithm>

const std::string titleCntThreads = "cntThreads";
const std::string titleDwSize = "dwSize";
const std::string titlePcPriClassBase = "pcPriClassBase";
const std::string titleSzExeFile = "szExeFile";
const std::string titleTh32ParentProcessID = "th32ParentProcessID";
const std::string titleTh32ProcessID = "th32ProcessID";
const std::string Title = "Running process on ";

size_t maxTitleCntThreads = titleCntThreads.size();
size_t maxTitleDwSize = titleDwSize.size();
size_t maxTitlePcPriClassBase = titlePcPriClassBase.size();
size_t maxTitleSzExeFile = titleSzExeFile.size();
size_t maxTitleTh32ParentProcessID = titleTh32ParentProcessID.size();
size_t maxTitleTh32ProcessID = titleTh32ProcessID.size();

struct Process {
    DWORD cntThreads = -1;              // Process amounts, that started by this process.
    DWORD dwSize = -1;                  // Size of structure in bytes.
    LONG pcPriClassBase = -1;           // Base priority of each thread, started by this process.
    WCHAR szExeFile[260];               // Process name.
    DWORD th32ParentProcessID = -1;     // Parents process ID.
    DWORD th32ProcessID = -1;           // Process ID.
    Process(DWORD cntThreads_,          DWORD dwSize_,
            LONG pcPriClassBase_,       WCHAR* szExeFile_,
            DWORD th32ParentProcessID_, DWORD th32ProcessID_) :
            cntThreads(cntThreads_),            dwSize(dwSize_),
            pcPriClassBase(pcPriClassBase_),    th32ParentProcessID(th32ParentProcessID_), 
            th32ProcessID(th32ProcessID_) {
        wmemcpy(szExeFile, szExeFile_, sizeof(szExeFile_));
    };
    ~Process() {};
    std::array<std::string, 6> const ConvertToStringArray() {
        std::stringstream ss;
        ss << cntThreads;
        std::string s1 = ss.str();

        ss << dwSize;
        std::string s2 = ss.str();

        std::string s3 = std::to_string(pcPriClassBase);

        char protoString[260];
        char defChar = ' ';
        WideCharToMultiByte(CP_ACP, 0, szExeFile, -1, protoString, 260, &defChar, NULL);
        std::string s4(protoString);
        s4.erase(std::remove(s4.begin(), s4.end(), 32), s4.end());
        s4.erase(std::remove(s4.begin(), s4.end(), -52), s4.end());


        ss << th32ParentProcessID;
        std::string s5 = ss.str();

        ss << th32ProcessID;
        std::string s6 = ss.str();

        return std::array<std::string, 6> {{s1, s2, s4, s3, s5, s6}};
    }
};

static auto getRunningProcesses() -> PROCESSENTRY32W {
    std::vector<std::wstring> processNames;
    HANDLE hProcessSnap;
    PROCESSENTRY32W pe32;
    // Создаем снимок всех процессов
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE) {
        std::cerr << "CreateToolhelp32Snapshot failed" << std::endl;
        exit(-1);
    }
    pe32.dwSize = sizeof(PROCESSENTRY32W);
    // Получаем информацию о первом процессе
    if (!Process32FirstW(hProcessSnap, &pe32)) {
        std::cerr << "Process32FirstW failed" << std::endl;
        CloseHandle(hProcessSnap);
        exit(-1);
    }
    return pe32;
}

static void fillProcessVector(PROCESSENTRY32W pr, std::vector<Process> &vct) {
    if (vct.size() != 0) vct.clear();
    HANDLE hProcessSnap;
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    do {
        vct.emplace_back(pr.cntThreads,
            pr.dwSize,
            pr.pcPriClassBase,
            pr.szExeFile,
            pr.th32ParentProcessID,
            pr.th32ProcessID);
    } while (Process32NextW(hProcessSnap, &pr));
    CloseHandle(hProcessSnap);
}

static auto getCurrentTime() -> char*{
    auto now = std::chrono::system_clock::now();
    std::time_t now_c = std::chrono::system_clock::to_time_t(now);
    std::tm* now_tm = std::localtime(&now_c);
    char buffer[20];
    strftime(buffer, sizeof(buffer), "%d/%m/%Y %H:%M:%S", now_tm);
    return buffer;
}

static size_t getNumberDigit(DWORD num) {
    size_t digit(0);
    for (digit; num > 0; ++digit) num /= 10;
    return digit > 0 ? digit : 1;
}

static void printWordLine(const std::array<std::string, 6>& words) {
    if (words[2].size() > 100) return;
    std::cout << "| ";
    std::vector<size_t> sizes = { maxTitleCntThreads, maxTitleDwSize, maxTitleSzExeFile, 
        maxTitlePcPriClassBase, maxTitleTh32ParentProcessID, maxTitleTh32ProcessID };

    for (size_t i(0); i < 6; ++i) {
        auto spacesAmount = sizes[i] - words[i].size();
        for (size_t i(0); i < spacesAmount; ++i) std::cout << " ";
        std::cout << words[i] << " | ";
    }
    std::cout << std::endl;
    size_t iters = maxTitleCntThreads + maxTitleSzExeFile + maxTitleDwSize + maxTitlePcPriClassBase + maxTitleTh32ParentProcessID + maxTitleTh32ProcessID + 19;
    for (size_t i(0); i < iters; ++i) std::cout << "-";
    std::cout << std::endl;
}

static void ConsoleOutput(std::vector<Process> pr) {
    // Print title.
    for (size_t i(0); i < Title.size() + 20 + 3; ++i) std::cout << "*";
    std::cout << std::endl;
    std::string ct = getCurrentTime();
    std::cout << "* " << Title << ct << " *" << std::endl;
    for (size_t i(0); i < Title.size() + 20 + 3; ++i) std::cout << "*";
    std::cout << std::endl;
    std::cout << std::endl;

    for (auto& process : pr) {
        if (getNumberDigit(process.cntThreads) > maxTitleCntThreads) maxTitleCntThreads = getNumberDigit(process.cntThreads);
        if (getNumberDigit(process.dwSize) > maxTitleDwSize) maxTitleDwSize = getNumberDigit(process.dwSize);
        char protoString[260];
        char defChar = ' ';
        WideCharToMultiByte(CP_ACP, 0, process.szExeFile, -1, protoString, 260, &defChar, NULL);
        std::string str(protoString);
        if (str.size() > maxTitleSzExeFile && str.size() < 100) {
#ifndef DEBUG
            std::cout << "*******************************" << std::endl
                      << "* BAD SYSTEM PROCESS CHECKING *" << std::endl
                      << "*******************************" << std::endl;
#endif // !DEBUG
            maxTitleSzExeFile = str.size();
            std::cout << str << std::endl;
        }
        if (getNumberDigit(process.pcPriClassBase) > maxTitlePcPriClassBase) maxTitlePcPriClassBase = getNumberDigit(process.pcPriClassBase);
        if (getNumberDigit(process.th32ParentProcessID) > maxTitleTh32ParentProcessID) maxTitleTh32ParentProcessID = getNumberDigit(process.th32ParentProcessID);
        if (getNumberDigit(process.th32ProcessID) > maxTitleTh32ProcessID) maxTitleTh32ProcessID = getNumberDigit(process.th32ProcessID);
    }

    size_t iters = maxTitleCntThreads + maxTitleSzExeFile + maxTitleDwSize + maxTitlePcPriClassBase + maxTitleTh32ParentProcessID + maxTitleTh32ProcessID + 19;
    for (size_t i(0); i < iters; ++i) std::cout << "-";
    std::cout << std::endl;
    printWordLine(std::array<std::string, 6> {titleCntThreads, titleDwSize, titleSzExeFile, 
        titlePcPriClassBase, titleTh32ParentProcessID, titleTh32ProcessID});

    for (auto& process : pr) {
        printWordLine(process.ConvertToStringArray());
    }

}

int main() {
    std::vector<Process> processes;
    auto process = getRunningProcesses();
    fillProcessVector(process, processes);
    ConsoleOutput(processes);
    return 0;
}