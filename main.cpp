#include <iostream>
#include <fstream>
#include "scanner.h"
#include "monitor.h"
#include "network_watcher.h"
#include "sandbox_logic.h"
#include <iostream>
#include "pe_analyzer.h"
using namespace std; 

int main() {
    Scanner scanner;
    Monitor monitor; 
    Sandbox sandbox; 
    string fileToScan = "C:\\Users\\jacob\\source\\repos\\malwarec\\x64\\Debug\\malwarec.exe"; // Replace with actual path

    cout << "[1] Scanning file..." << endl;
    bool isMalicious = scanner.scanFile(fileToScan, "signatures.txt"); 
    bool isMalicious_unencrypted = scanner.scanFile(fileToScan, "unencrypted_signatures.txt"); 

    cout << "malicious signature found: (0/1) " << isMalicious << endl;
    cout << "malicious unencrypted signature found: (0/1) " << isMalicious_unencrypted << endl;

    
    if (isMalicious || isMalicious) {
        cout << "[2] Running in sandbox for further analysis..." << endl;
        sandbox.executeInSandbox(fileToScan);
    }



    return 0;
}



