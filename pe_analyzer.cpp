#include "pe_analyzer.h"
#include <windows.h>
#include <iostream>
#include <vector>

using namespace std;

static vector<string> suspiciousAPIs = {
    "GetAsyncKeyState", "SetWindowsHookExA", "SetWindowsHookExW",
    "CreateRemoteThread", "VirtualAllocEx", "WriteProcessMemory", "KEYEVENTF_"
}; 

DWORD RvaToOffset(DWORD rva, PIMAGE_NT_HEADERS64 ntHeaders, PIMAGE_SECTION_HEADER sectionHeaders, int numSections) {
    for (int i = 0; i < numSections; ++i) {
        DWORD sectionVA = sectionHeaders[i].VirtualAddress;
        DWORD sectionSize = sectionHeaders[i].Misc.VirtualSize;
        if (rva >= sectionVA && rva < sectionVA + sectionSize) {
            DWORD delta = rva - sectionVA;
            return sectionHeaders[i].PointerToRawData + delta;
        }
    }
    return 0;
} 

bool PEAnalyzer::scanImports(const string& filepath, HANDLE hProcess) { 

    HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        cerr << "[ERROR] Cannot open file: " << filepath << endl;
        return false;
    }

    HANDLE hMapping = CreateFileMappingA(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!hMapping) {
        CloseHandle(hFile);
        cerr << "[ERROR] Failed to create file mapping" << endl;
        return false;
    }

    LPVOID baseAddr = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    if (!baseAddr) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        cerr << "[ERROR] Failed to map view of file" << endl;
        return false;
    }

    auto dosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddr);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) {
        cerr << "[ERROR] Invalid DOS signature" << endl;
        UnmapViewOfFile(baseAddr);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    auto ntHeaders = reinterpret_cast<PIMAGE_NT_HEADERS64>((BYTE*)baseAddr + dosHeader->e_lfanew);
    if (ntHeaders->Signature != IMAGE_NT_SIGNATURE) {
        cerr << "[ERROR] Invalid NT signature" << endl;
        UnmapViewOfFile(baseAddr);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    PIMAGE_SECTION_HEADER sectionHeaders = IMAGE_FIRST_SECTION(ntHeaders);
    int numSections = ntHeaders->FileHeader.NumberOfSections;

    DWORD importDirRVA = ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    if (importDirRVA == 0) {
        cerr << "[INFO] No import table present" << endl;
        UnmapViewOfFile(baseAddr);
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return false;
    }

    DWORD importDirOffset = RvaToOffset(importDirRVA, ntHeaders, sectionHeaders, numSections);
    PIMAGE_IMPORT_DESCRIPTOR importDesc = reinterpret_cast<PIMAGE_IMPORT_DESCRIPTOR>((BYTE*)baseAddr + importDirOffset);

    while (importDesc->Name != 0) {
        DWORD nameOffset = RvaToOffset(importDesc->Name, ntHeaders, sectionHeaders, numSections);
        const char* dllName = reinterpret_cast<const char*>((BYTE*)baseAddr + nameOffset);

        DWORD thunkRVA = importDesc->OriginalFirstThunk ? importDesc->OriginalFirstThunk : importDesc->FirstThunk;
        DWORD thunkOffset = RvaToOffset(thunkRVA, ntHeaders, sectionHeaders, numSections);
        PIMAGE_THUNK_DATA64 thunkData = reinterpret_cast<PIMAGE_THUNK_DATA64>((BYTE*)baseAddr + thunkOffset);

        while (thunkData->u1.AddressOfData != 0) {
            if (!(thunkData->u1.Ordinal & IMAGE_ORDINAL_FLAG64)) {
                DWORD funcOffset = RvaToOffset((DWORD)thunkData->u1.AddressOfData, ntHeaders, sectionHeaders, numSections);
                PIMAGE_IMPORT_BY_NAME funcName = reinterpret_cast<PIMAGE_IMPORT_BY_NAME>((BYTE*)baseAddr + funcOffset);

                string name(reinterpret_cast<char*>(funcName->Name)); 
                for (const string& suspect : suspiciousAPIs) {
                    if (name.find(suspect) != string::npos) {
                        cout << "[!] Suspicious API Detected: " << name << " in DLL: " << dllName << endl;
                    }
                }
            }
            ++thunkData;
        }
        ++importDesc;
    }
    cout << "last error in pe analyzer: "<< GetLastError() << endl;
    UnmapViewOfFile(baseAddr);
    CloseHandle(hMapping);
    CloseHandle(hFile);
    return true;
}
