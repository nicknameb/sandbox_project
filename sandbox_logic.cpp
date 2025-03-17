#include "sandbox_logic.h"
#include <iostream>
#include <windows.h>

using namespace std; 

void Sandbox::executeInSandbox(const string& filename) {
    cout << "Running " << filename << " in sandbox..." << endl;

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;

    if (CreateProcessA(NULL, const_cast<char*>(filename.c_str()), NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, NULL, &si, &pi)) {
        cout << "Suspended Process Created! PID: " << pi.dwProcessId << endl;
        ResumeThread(pi.hThread);
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
    else {
        cerr << "Failed to run file in sandbox!" << endl;
    }
}
