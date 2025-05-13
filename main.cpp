#include <iostream>
#include <fstream>
#include "scanner.h"
#include "monitor.h"
#include "network_watcher.h"
#include "sandbox_logic.h"
#include "pe_analyzer.h" 
#include <windows.h> 
#include "sandbox_vm.h"
using namespace std; 

int main() { 
    



    const string vboxPath = "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe"; 
    const string vmName = "SandBoxVM"; 
    const string current_snapshot = "Snapshot 30";  
    const string guestfile_path = "C:\\Users\\jacob\\Downloads\\malware_folder\\"; 

    Sandbox_vm sandbox_vm;
    Scanner scanner;
    Monitor monitor; 
    PEAnalyzer peanalyzer;
    Sandbox sandbox; 
    string fileToScan = "C:\\Users\\jacob\\source\\repos\\registry_test2\\x64\\Debug\\registry_test2.exe"; // Replace with actual path

    cout << "[1] Scanning file..." << endl;
    bool hashsignature_found = scanner.scanFile(fileToScan, "signatures.txt"); 
    bool unencrypted_signature_found = scanner.scanFile(fileToScan, "unencrypted_signatures.txt"); 

    cout << "unencrypted signature found: (0/1)" << unencrypted_signature_found << endl;

    bool sus_imports = peanalyzer.scanImports(fileToScan);
    cout <<"containts suspicious improts: (0/1) "<< sus_imports << endl; 

    if (true) {
        cout << "[2] Running in sandbox for further analysis..." << endl;
        sandbox.executeInSandbox(fileToScan);
    }   

    sandbox_vm.RunVirtualBoxVM(vboxPath, vmName, current_snapshot, fileToScan, guestfile_path);

    return 0;
}



