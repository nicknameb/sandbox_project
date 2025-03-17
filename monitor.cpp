#include "monitor.h"
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>

using namespace std; 

void Monitor::monitorProcesses() {
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); 

    if (hSnap == INVALID_HANDLE_VALUE)
    {
        return;
    } 

    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(procEntry);

    if (Process32First(hSnap, &procEntry)) {
        do {
            wcout << L"Running Process: " << procEntry.szExeFile << endl;
        } while (Process32Next(hSnap, &procEntry));
    }
    CloseHandle(hSnap);
}
