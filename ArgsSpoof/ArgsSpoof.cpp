#include <iostream>
#include <string>
#include <Windows.h>
#include <fstream>
#include "PEBex.h"
#include "winiternal.h"


FARPROC fpNtQueryInformationProcess = GetProcAddress(LoadLibraryA("ntdll"), "NtQueryInformationProcess");
_NtQueryInformationProcess NtQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;

LPCWSTR charToWchar(const char* char_str) {
    size_t len = 0;
    mbstowcs_s(&len, nullptr, 0, char_str, _TRUNCATE);
    wchar_t* wchar_str = new wchar_t[len];
    mbstowcs_s(&len, wchar_str, len, char_str, _TRUNCATE);
    return wchar_str;
}

LPPROCESS_INFORMATION CreateSuspendedProcess(LPCSTR targetImage) {
    LPSTARTUPINFOA targetImageStartupInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION targetImageProcessInfo = new PROCESS_INFORMATION();
    if (!CreateProcessA(
        targetImage,
        NULL,
        NULL,
        NULL,
        FALSE,
        CREATE_SUSPENDED,
        NULL,
        NULL,
        targetImageStartupInfo,
        targetImageProcessInfo)) {
        std::cerr << "Failed to create suspended process. Error: " << GetLastError() << std::endl;
        return NULL;
    }
    return targetImageProcessInfo;
}

bool GetProcessBasicInformation(HANDLE hProcess, PROCESS_BASIC_INFORMATION* pbi) {
    NTSTATUS status = NtQueryInformationProcess(hProcess, ProcessBasicInformation, pbi, sizeof(PROCESS_BASIC_INFORMATION), NULL);
    if (!NT_SUCCESS(status)) {
        std::cerr << "Unable to query process information. Error: " << GetLastError() << std::endl;
        return false;
    }
    std::cout << "Address of PEB: " << std::hex << pbi->PebBaseAddress << std::endl;
    return true;
}

bool ReadPEB(HANDLE hProcess, PEB* peb, LPCVOID pebBaseAddress) {
    if (!ReadProcessMemory(hProcess, pebBaseAddress, peb, sizeof(PEB), NULL)) {
        std::cerr << "Unable to read PEB. Error: " << GetLastError() << std::endl;
        return false;
    }
    std::cout << "PEB mapped at: " << std::hex << peb << std::endl;
    return true;
}

bool ReadProcessParameters(HANDLE hProcess, PEB* peb, PRTL_USER_PROCESS_PARAMETERS pParams) {
    if (!ReadProcessMemory(hProcess, peb->ProcessParameters, pParams, sizeof(RTL_USER_PROCESS_PARAMETERS), NULL)) {
        std::cerr << "Unable to read Process Parameters. Error: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}

bool WriteSpoofedCommandLine(HANDLE hProcess, PRTL_USER_PROCESS_PARAMETERS pParams, PEB peb, const wchar_t* spoofedCommand) {
    DWORD dwLength = lstrlenW(spoofedCommand) * sizeof(WCHAR) + 1;
    DWORD dwMaximumLength = dwLength + sizeof(WCHAR);

    if (!WriteProcessMemory(hProcess, pParams->CommandLine.Buffer, spoofedCommand, dwMaximumLength, NULL)) {
        std::cerr << "Unable to write spoofed Command Line. Error: " << GetLastError() << std::endl;
        return false;
    }

    PVOID pCammndLen = (LPBYTE)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.Length);
    PVOID pMaxLen = (LPBYTE)peb.ProcessParameters + offsetof(RTL_USER_PROCESS_PARAMETERS, CommandLine.MaximumLength);


    if (!WriteProcessMemory(
        hProcess,
        pCammndLen,
        &dwLength,
        sizeof(DWORD),
        NULL)) {
        std::cerr << "Unable to update Command Line length. Error: " << GetLastError() << std::endl;
        return false;
    }
    if (!WriteProcessMemory(
        hProcess,
        pMaxLen,
        &dwMaximumLength,
        sizeof(DWORD),
        NULL)) {
        std::cerr << "Unable to update Command Line maximum length. Error: " << GetLastError() << std::endl;
        return false;
    }
    return true;
}



LPWSTR formatCommand(const wchar_t* commandLine) {
    size_t len = wcslen(commandLine);
    bool prependSpace = commandLine[0] != L' ';
    wchar_t* formattedStr = new wchar_t[len + 1 + prependSpace];

    if (prependSpace) {
        formattedStr[0] = L' ';
        wcscpy_s(&formattedStr[1], len + 1, commandLine);
    }
    else {
        wcscpy_s(formattedStr, len + 1, commandLine);
    }
    return formattedStr;
}


void DebugOutputCommandLine(const char* targetExecutable, HANDLE hProcess, PRTL_USER_PROCESS_PARAMETERS pParams) {
    DWORD dwSize = pParams->CommandLine.Length;
    PVOID pCommandLineBuffer = malloc(dwSize);
    std::cout << "\nRunning: " << targetExecutable;
    if (ReadProcessMemory(hProcess, pParams->CommandLine.Buffer, pCommandLineBuffer, dwSize, NULL)) {
        std::wcout << (wchar_t*)pCommandLineBuffer << std::endl;
    }
    else {
        std::cerr << "Unable to retrieve Command Line. Error: " << GetLastError() << std::endl;
    }
    free(pCommandLineBuffer);
}


int main(int argc, char* argv[]) {
    bool inputMode = false;
    const char* targetExecutable = nullptr;
    std::wstring spoofedCommand;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "--input") {
            inputMode = true;
        }
        else if (!targetExecutable) {
            targetExecutable = argv[i];
        }
        else {
            spoofedCommand = formatCommand(charToWchar(argv[i]));
        }
    }

    if (!targetExecutable) {
        std::cerr << "Usage: " << argv[0] << " <targetExecutable> [--input or <spoofedCommand>]\n";
        return 1;
    }

    if (!inputMode && spoofedCommand.empty()) {
        std::cerr << "No command provided to spoof. Exiting.\n";
        return 1;
    }


    LPPROCESS_INFORMATION pProcess = CreateSuspendedProcess(targetExecutable);
    if (!pProcess) {
        return 1;
    }

    CONTEXT context = {};
    PROCESS_BASIC_INFORMATION pbi = {};
    if (!GetProcessBasicInformation(pProcess->hProcess, &pbi)) {
        return 1;
    }

    PEB peb = {};
    if (!ReadPEB(pProcess->hProcess, &peb, pbi.PebBaseAddress)) {
        return 2;
    }

    RTL_USER_PROCESS_PARAMETERS pParams = {};
    if (!ReadProcessParameters(pProcess->hProcess, &peb, &pParams)) {
        return 3;
    }

    if (inputMode) {
        std::string line;
        std::cout << "Enter spoofed command: ";
            
        while (line.empty()) {
            std::getline(std::cin, line);
        }

        spoofedCommand = formatCommand(charToWchar(line.c_str()));
        if (!WriteSpoofedCommandLine(pProcess->hProcess, &pParams, peb, spoofedCommand.c_str())) {
            return 4;
        }
    }
    else {
        if (!WriteSpoofedCommandLine(pProcess->hProcess, &pParams, peb, spoofedCommand.c_str())) {
            return 4;
        }
    }

    DebugOutputCommandLine(targetExecutable, pProcess->hProcess, &pParams);


    ResumeThread(pProcess->hThread);
    WaitForSingleObject(pProcess->hProcess, INFINITE);
    WaitForSingleObject(pProcess->hThread, INFINITE);


    return 0;
}


