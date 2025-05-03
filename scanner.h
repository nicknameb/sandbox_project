#pragma once

#include <string>
#include <vector> 
#include <windows.h>
using namespace std; 

class Scanner {
public:
    // Scans a file for known malicious signatures
    bool scanFile(const string& filename, const string& sig);  

    bool scanSuspendedProcess(HANDLE hProcess);
};

// Loads malware signatures from a file (hex-encoded, one per line)
vector<string> loadSignaturesFromFile(const string& path);
