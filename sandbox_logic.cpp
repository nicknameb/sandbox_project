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
    PEAnalyzer peanalyzer;

    cout << "Running " << filename << " in sandbox..." << endl;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessA(NULL, const_cast<char*>(filename.c_str()), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {

        cout << "Suspended Process Created! PID: " << pi.dwProcessId << endl;


        char name_buffer[MAX_PATH];
        GetModuleFileNameExA(pi.hProcess, NULL, (LPSTR)name_buffer, MAX_PATH);
        bool sus_api = scanner.scanSuspendedProcess(pi.hProcess);
        cout << "found suspicious api: " << sus_api << " in process: "<< name_buffer << endl;

        bool suspicous_imprts = peanalyzer.scanImports(filename); 
        

        if (sus_api || suspicous_imprts)
        { 
            cout << "malicious signature detected, did not run file" << endl; 
            return;
        } 

        ResumeThread(pi.hThread); 
        

        WaitForSingleObject(pi.hProcess, INFINITE); 


        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        cerr << "Failed to run file in sandbox!" << endl; 
        cout << GetLastError() << endl;
    }
}

