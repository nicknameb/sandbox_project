#include <iostream>
#include <fstream>
#include "scanner.h"
#include "monitor.h"
#include "network_watcher.h"
#include "sandbox_logic.h"
#include <iostream>

using namespace std; 

int main() {
    Scanner scanner;
    Monitor monitor;
    NetworkWatcher networkWatcher;
    Sandbox sandbox;

    string fileToScan = "example.exe"; // Replace with actual path

    cout << "[1] Scanning file..." << endl;
    bool isMalicious = scanner.scanFile(fileToScan);

    if (isMalicious) {
        cout << "[2] Running in sandbox for further analysis..." << endl;
        sandbox.executeInSandbox(fileToScan);
    }

    cout << "[3] Monitoring system processes..." << endl;
    monitor.monitorProcesses();

    cout << "[4] Monitoring network traffic..." << endl;
    networkWatcher.monitorConnections();

    return 0;
}


