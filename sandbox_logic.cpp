#include "sandbox_logic.h"
#include <iostream>
#include <windows.h>
#include "network_watcher.h" 
#include "scanner.h" 
#include <Psapi.h> 
#include "pe_analyzer.h"
using namespace std;  



void Sandbox::executeInSandbox(const string& filename) { 
    NetworkWatcher networkWatcher; 
    Scanner scanner; 

    cout << "Running " << filename << " in sandbox..." << endl;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessA(NULL, const_cast<char*>(filename.c_str()), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {

        cout << "Suspended Process Created! PID: " << pi.dwProcessId << endl;


        char name_buffer[MAX_PATH];
        GetModuleFileNameExA(pi.hProcess, NULL, (LPSTR)name_buffer, MAX_PATH);
        bool sus_api = scanner.scanSuspendedProcess(pi.hProcess);
        cout << "found suspicious api in suspended process (0/1): " << sus_api << " in process: "<< name_buffer << endl;


        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        cerr << "Failed to create process!" << endl; 
        cout << GetLastError() << endl;
    }
}


