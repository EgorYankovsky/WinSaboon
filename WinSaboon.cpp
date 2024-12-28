#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <vector>
#include <string>
#include <chrono>
#include <ctime>

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
    strftime(buffer, sizeof(buffer), "%Y %m %d %H:%M:%S", now_tm);
    return buffer;
}

static size_t getNumberDigit(DWORD num) {
    size_t digit(0);
    for (digit; num > 0; ++digit) num /= 10;
    return digit > 0 ? digit : 1;
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
        if (getNumberDigit(process.pcPriClassBase) > maxTitlePcPriClassBase) maxTitlePcPriClassBase = getNumberDigit(process.pcPriClassBase);
        if (getNumberDigit(process.th32ParentProcessID) > maxTitleTh32ParentProcessID) maxTitleTh32ParentProcessID = getNumberDigit(process.th32ParentProcessID);
        if (getNumberDigit(process.th32ProcessID) > maxTitleTh32ProcessID) maxTitleTh32ProcessID = getNumberDigit(process.th32ProcessID);
    }

    size_t iters = maxTitleCntThreads + maxTitleDwSize + maxTitlePcPriClassBase + maxTitleTh32ParentProcessID + maxTitleTh32ProcessID + 16;
    for (size_t i(0); i < iters; ++i) std::cout << "-";
    std::cout << std::endl;
    std::cout << "| " << titleCntThreads << " | " << titleDwSize << " | " <<
        titlePcPriClassBase << " | " << titleTh32ParentProcessID << " | " <<
        titleTh32ProcessID << " |";
    std::cout << std::endl;
    for (size_t i(0); i < iters; ++i) std::cout << "-";
    std::cout << std::endl;
}

int main() {
    std::vector<Process> processes;
    auto process = getRunningProcesses();
    fillProcessVector(process, processes);
    ConsoleOutput(processes);
    return 0;
}