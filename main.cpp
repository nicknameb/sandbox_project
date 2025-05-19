#include <iostream>
#include <fstream>
#include "scanner.h"
#include "monitor.h"
#include "network_watcher.h"
#include "sandbox_logic.h"
#include "pe_analyzer.h" 
#include <windows.h> 
#include "sandbox_vm.h"  
#include <filesystem>
using namespace std; 

int main(int argc, char* argv[]) {

    if (argc < 2)
    {  
        cout << "usage: antivirus_path.exe <file>" << endl;
        return 1;
    }
    string fileToScan = argv[1]; 
    string username = "JACOB2";      //this is hard coded because the users need to access the vm anyway
    string password = "cyber2025";  //theres no point in hiding password
 
    char path_buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path_buffer);
    string current_dir(path_buffer); 
    string log_file = current_dir + "\\scan_output.txt";
    ofstream log(log_file, ios::app);

    const string vboxPath = "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe"; //default VBOX installation, a different path will result in issues
    const string vmName = "SandBoxVM Clone"; 
    const string current_snapshot = "current snapshot";  
    const string guestfile_path = "C:\\Regshot_folder\\";

    Sandbox_vm sandbox_vm;
    Scanner scanner;
    Monitor monitor; 
    PEAnalyzer peanalyzer;
    ScanProcess scanproc;

    log << "[1] Scanning file..." << endl;
    bool hashsignature_found = scanner.scanFile(fileToScan, "signatures.txt"); 

    if (hashsignature_found)
    { 
        log << "SUSPICIOUS_SIGNATURE FOUND" << endl;
    }
    

    bool sus_imports = peanalyzer.scanImports(fileToScan);
    
    if (sus_imports)
    { 
        log << "SUSPICIOUS_IMPORTS FOUND" << endl;
    } 

    
    log << "testing suspended process for further analysis" << endl;
    scanproc.ScanCreatedProcess(fileToScan);
    

    sandbox_vm.RunVirtualBoxVM(vboxPath, vmName, current_snapshot, fileToScan, guestfile_path, username, password);

    return 0;
}
