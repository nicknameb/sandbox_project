#include "scanner.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <cctype>
#include <windows.h>
using namespace std;  

static vector<string> suspiciousAPIs = {
    "GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "KEYEVENTF_", "GetAsyncKeyState"
}; 



vector<string> loadSignaturesFromFile(const string& path) {
    ifstream file(path);
    vector<vector<unsigned char>> signature_vector;  
    vector<string> signatures;              //actuacl vector of string signatures

    if (!file) {
        cerr << "[ERROR] Failed to open signature file: " << path << endl;
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

    ifstream file(filename, ios::binary);
    ostringstream contents;
    contents << file.rdbuf();
    string fileData = contents.str();

    //cout << "file data: "<< fileData << endl;

    if (!file) {
        cerr << "[ERROR] File not found: " << filename << endl;
        return false;
    }

    vector<unsigned char> buffer((istreambuf_iterator<char>(file)), {});
    vector<string> signatures = loadSignaturesFromFile(signature_file);

    for (const auto& sig : signatures) { 

        if (fileData.find(sig) != string::npos) {
            cout << "[!] Suspicious signature/API detected: " << sig << " in file: " << filename << endl;
            return true;
        }
    }


    cout << "[SAFE] No threat detected in " << filename << endl;
    return false;
} 


bool Scanner::scanSuspendedProcess(HANDLE hProcess) {
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
                            cout << "[!] Found suspicious API: " << api << " in memory" << endl;
                            flag = true;
                        }
                    }

                }
            }

            addr = static_cast<LPCBYTE>(mbi.BaseAddress) + mbi.RegionSize;
        } 
        else { cout << "virtualqueryex returned 0" << endl; }
    } 
    return flag;
}


