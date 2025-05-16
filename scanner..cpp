#include "scanner.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <cctype>
#include <windows.h> 
#include <fstream> 
using namespace std;  

static vector<string> suspiciousAPIs = {
    "GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "KEYEVENTF_", "GetAsyncKeyState"
}; 

vector<string> loadSignaturesFromFile(const string& path) { 
    char path_buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path_buffer);
    string current_dir(path_buffer);
    string log_file = current_dir + "\\scan_output.txt";

    ofstream log(log_file, ios::app);

    ifstream file(path);
    vector<vector<unsigned char>> signature_vector;  
    vector<string> signatures;              //actuacl vector of string signatures

    if (!file) {
        log << "ERROR: Failed to open signature file: " << path << endl;
        return signatures;
    }

    string line;
    while (getline(file, line)) {
        if (!line.empty()) {
            signatures.push_back(line); // plain text
        }
    }

    return signatures;
}


bool Scanner::scanFile(const string& filename, const string& signature_file) { 
    char path_buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path_buffer);
    string current_dir(path_buffer);
    string log_file = current_dir + "\\scan_output.txt";

    ofstream log(log_file, ios::app);

    ifstream file(filename, ios::binary);
    ostringstream contents;
    contents << file.rdbuf();
    string fileData = contents.str();

    if (!file) {
        log << "ERROR: File not found: " << filename << endl;
        return false;
    }

    vector<unsigned char> buffer((istreambuf_iterator<char>(file)), {});
    vector<string> signatures = loadSignaturesFromFile(signature_file);

    for (const auto& sig : signatures) { 

        if (fileData.find(sig) != string::npos) {
            log << "SUSPICIOUS_SIGNATURE OR API FOUND: " << sig << " in file: " << filename << endl;
            return true;
        }
    }


    log << "No threat signature  detected in " << filename << endl;
    return false;
} 


bool Scanner::scanSuspendedProcess(HANDLE hProcess) {  
    char path_buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path_buffer);
    string current_dir(path_buffer);
    string log_file = current_dir + "\\scan_output.txt";

    ofstream log(log_file, ios::app); 

    SYSTEM_INFO sysInfo;
    GetSystemInfo(&sysInfo);  //get the size of the page

    LPCVOID addr = sysInfo.lpMinimumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;

    bool flag = false; 

    while (addr < sysInfo.lpMaximumApplicationAddress) {
        if (VirtualQueryEx(hProcess, addr, &mbi, sizeof(mbi)) != 0)
        {

            if (mbi.State == MEM_COMMIT && (mbi.Protect & (PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_READONLY | PAGE_READWRITE))) {
                vector<char> buffer(mbi.RegionSize);
                SIZE_T bytesRead;

                if (ReadProcessMemory(hProcess, addr, buffer.data(), buffer.size(), &bytesRead)) {
                    string memDump(buffer.begin(), buffer.begin() + bytesRead);

                    for (const auto& api : suspiciousAPIs) {
                        auto it = search(buffer.begin(), buffer.begin() + bytesRead,api.begin(), api.end());
                        if (it != buffer.begin() + bytesRead) {
                            log << "SUSPICIOUS_API FOUND " << api << " in memory" << endl;
                            flag = true;
                        }
                    }

                }
            }

            addr = static_cast<LPCBYTE>(mbi.BaseAddress) + mbi.RegionSize;
        } 
        else  
        {  
            log << "ERROR in scanning suspended process: virtualqueryex returned 0" << endl;  
        }
    } 
    return flag;
}
