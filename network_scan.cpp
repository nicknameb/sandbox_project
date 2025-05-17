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
#include <iostream>
#include <string> 
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

bool isTorExitNode(const  string& ipAddress) {
    HINTERNET hInternet = InternetOpenA("TorCheck", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hInternet) {
        cerr << "Failed to open internet handle." << endl;
        return false;
    }

    string url = "https://www.dan.me.uk/torcheck?ip=" + ipAddress;
    HINTERNET hFile = InternetOpenUrlA(hInternet, url.c_str(), NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hFile) {
        cerr << "Failed to open URL: " << url << endl;
        InternetCloseHandle(hInternet);
        return false;
    }

    char buffer[4096];
    DWORD bytesRead;
    string response;

    while (InternetReadFile(hFile, buffer, sizeof(buffer) - 1, &bytesRead) && bytesRead > 0) {
        buffer[bytesRead] = 0;
        response += buffer;
    }

    InternetCloseHandle(hFile);
    InternetCloseHandle(hInternet);

    if (response.find("is a TOR Exit Node") != string::npos)
    {
        return true;
    }

    return false;
}

bool Survey_connections(DWORD targetPID) {
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
        cerr << "Failed to get TCP table" << endl;
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
            if (isTorExitNode(inet_ntoa(remoteAddr)))
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

    cout << "scanning for suspicious tor connections..." << endl; 

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
                bool has_sus_connections = Survey_connections(pe32.th32ProcessID);  

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
