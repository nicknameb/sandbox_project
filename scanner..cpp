#include "scanner.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <cctype>

using namespace std; 

unsigned char hexToByte(const string& hex) {
    return static_cast<unsigned char>(stoi(hex, nullptr, 16));
}

vector<unsigned char> hexStringToBytes(const string& hexStr) {
    vector<unsigned char> bytes; 

    for (size_t i = 0; i < hexStr.length(); i += 2) {          
        string byteString = hexStr.substr(i, 2);
        if (byteString.length() == 2 && ( isxdigit(byteString[0]) && isxdigit(byteString[1]) )) {
            bytes.push_back(hexToByte(byteString));
        }
    } 

    return bytes;
}

vector<vector<unsigned char>> loadSignaturesFromFile(const string& path) {
    ifstream file(path);
    vector<vector<unsigned char>> signatures;

    if (!file) {
        cerr << "[ERROR] Failed to open signature file: " << path << endl;
        return signatures;
    }

    string line;
    while (getline(file, line)) {
        if (!line.empty()) {
            signatures.push_back(hexStringToBytes(line));
        }
    }

    return signatures;
}


bool Scanner::scanFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "[ERROR] File not found: " << filename << endl;
        return false;
    }

    vector<unsigned char> buffer((istreambuf_iterator<char>(file)), {});
    vector<vector<unsigned char>> signatures = loadSignaturesFromFile("signatures.txt");

    for (const auto& sig : signatures) {
        if (search(buffer.begin(), buffer.end(), sig.begin(), sig.end()) != buffer.end()) {
            cout << "[ALERT] Malicious signature found in " << filename << "!" << endl;
            return true;
        }
    }

    cout << "[SAFE] No threat detected in " << filename << "." << endl;
    return false;
}
