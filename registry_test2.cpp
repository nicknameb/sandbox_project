#include <windows.h>
#include <tchar.h>
#include <iostream>

using namespace std;
int main() {
    HKEY hKey;
    LPCSTR keyPath = "Software\\Microsoft\\Windows\\CurrentVersion\\Run";
    LPCSTR valueName = "FakeMalware123";
    LPCSTR exePath = "%APPDATA%\\malware_simulator.exe";  

    // Open or create the registry key
    LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, keyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_SET_VALUE, NULL, &hKey, NULL);

    if (result == ERROR_SUCCESS) {
        // Set the registry value
        result = RegSetValueExA(hKey, valueName, 0, REG_SZ, (const BYTE*)exePath, strlen(exePath) + 1);
        if (result == ERROR_SUCCESS) {
            cout << "[+] Registry Run key added successfully!" << std::endl;
        }
        else {
            cerr << "[-] Failed to set registry value. Error: " << result << std::endl;
        }

        // Close the registry key
        RegCloseKey(hKey);
    }
    else {
        cerr << "[-] Failed to open registry key. Error: " << result << std::endl;
    }

    return 0;
}
