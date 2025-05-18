#include "sandbox_logic.h"
#include <iostream>
#include <windows.h>
#include "scanner.h" 
#include <Psapi.h> 
#include "pe_analyzer.h" 
#include <fstream> 
using namespace std;  



void ScanProcess::ScanCreatedProcess(const string& filename) {  
    Scanner scanner; 
    char path_buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path_buffer);
    string current_dir(path_buffer);
    string log_file = current_dir + "\\scan_output.txt";

    ofstream log(log_file, ios::app);

    size_t pos = filename.find_last_of("\\/");  //get name of malware itself
    string app_name = filename.substr(pos + 1); 

    log << "Running " << app_name << " in " << endl;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessA(NULL, const_cast<char*>(filename.c_str()), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {

        log << "Suspended Process Created! PID: " << pi.dwProcessId << endl;

        bool sus_api = scanner.scanSuspendedProcess(pi.hProcess);  

        if (sus_api)
        {
            log << "SUSPICIOUS_API FOUND IN SUSPENDED PROCESS: " << app_name << endl;
        }

        TerminateProcess(pi.hProcess, 1); 
        WaitForSingleObject(pi.hProcess, 500); 
        
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        log << "ERROR: Failed to create process!" << endl; 
        log << GetLastError() << endl;
    }
}
