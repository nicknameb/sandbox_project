#include <iostream>
#define _WINSOCK_DEPRECATED_NO_WARNINGS 
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <iostream>
#include <set> 
#include <windows.h>
#include <wininet.h>
#include <fstream>
#include <string>  
#include <unordered_set>
#include <TlHelp32.h> 
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib") 
#pragma comment(lib, "wininet.lib")
using namespace std;

wchar_t* ConvertStringToWChar(const string& str) {
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, NULL, 0);
    wchar_t* wstr = new wchar_t[size_needed];
    MultiByteToWideChar(CP_UTF8, 0, str.c_str(), -1, wstr, size_needed);
    return wstr;
} 

string WCharToString(const wchar_t* wstr) {
    if (!wstr) return "";

    int size_needed = WideCharToMultiByte(CP_UTF8, 0, wstr, -1, nullptr, 0, nullptr, nullptr);
    string result(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &result[0], size_needed, nullptr, nullptr);
    result.pop_back(); 
    return result;
} 

unordered_set<string> LoadTorIPs(const string& filename) 
{
    unordered_set<string> torIPs;
    ifstream file(filename);
    string line;
    while (getline(file, line)) {
        if (!line.empty()) {
            torIPs.insert(line);
        }
    }
    return torIPs;
} 

bool isTorExitNode(const string& ipAddress, const unordered_set<string>& torIPs) {
    return torIPs.find(ipAddress) != torIPs.end();
}

bool Survey_connections(DWORD targetPID, unordered_set<string> torIPs) {
    bool flag = false;
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {    
        cerr << "WSAStartup failed" << endl;
        return false;
    }

    PMIB_TCPTABLE_OWNER_PID tcpTable;     
    DWORD size = 0;
    GetExtendedTcpTable(nullptr, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0); 
    tcpTable = (PMIB_TCPTABLE_OWNER_PID)malloc(size);

    if (GetExtendedTcpTable(tcpTable, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0) != NO_ERROR) {
        cout << "Failed to get TCP table" << endl;
        free(tcpTable);                
        WSACleanup();
        return false;
    }

    cout << "TCP Connections for PID: " << targetPID << endl;

    for (DWORD i = 0; i < tcpTable->dwNumEntries; i++) {
        MIB_TCPROW_OWNER_PID row = tcpTable->table[i];   

        if (row.dwOwningPid == targetPID)
        {
            in_addr localAddr, remoteAddr;           
            localAddr.S_un.S_addr = row.dwLocalAddr;
            remoteAddr.S_un.S_addr = row.dwRemoteAddr;

            unsigned short localPort = ntohs((u_short)row.dwLocalPort); 
            unsigned short remotePort = ntohs((u_short)row.dwRemotePort);

            cout << "Local: " << inet_ntoa(localAddr) << ":" << localPort 
                << " | Remote: " << inet_ntoa(remoteAddr) << ":" << remotePort
                << " | State: " << row.dwState << endl;
            if (isTorExitNode(inet_ntoa(remoteAddr), torIPs))
            { 
                flag = true;
            }
        }
    }

    free(tcpTable);       
    WSACleanup(); 
    
    return flag;
}


int main(int argc, char* argv[])
{
    if (argc < 2)
    { 
        cout << "not enough args for network scan" << endl; 
        return 1;
    } 
    string process_name = argv[1]; 
   
    bool is_alive = true; 

    cout << "scanning for suspicious tor connections in application..." << process_name <<  endl; 

    unordered_set<string> torIPs = LoadTorIPs("C:\\Regshot_folder\\tor_nodes.txt");
 
    PROCESSENTRY32 pe32;

    pe32.dwSize = sizeof(pe32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    Process32First(snapshot, &pe32); 

    while (is_alive)  
    { 
        is_alive = false;

        do {

            if (wcscmp(pe32.szExeFile, ConvertStringToWChar(process_name)) == 0)
            { 
                cout << WCharToString(pe32.szExeFile) << endl;
                bool has_sus_connections = Survey_connections(pe32.th32ProcessID, torIPs);

                if (has_sus_connections)
                { 
                    cout << "process connects to tor nodes" << endl;
                } 

                is_alive = true;
            } 
        } while (Process32Next(snapshot, &pe32));  

        Sleep(3000);
    }

    
    CloseHandle(snapshot);

    return 0;
}
