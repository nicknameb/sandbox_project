#include <iostream>
#include <fstream>
#include <vector>

using namespace std; 
bool scanFile(const string& filename) {
    ifstream file(filename, ios::binary);
    if (!file) {
        cerr << "File not found: " << filename << endl;
        return false;
    }

    vector<unsigned char> buffer((istreambuf_iterator<char>(file)), {});

    // Example signature: Fake malware signature "ABCD1234"
    vector<unsigned char> signature = { 'A', 'B', 'C', 'D', '1', '2', '3', '4' };

    if (search(buffer.begin(), buffer.end(), signature.begin(), signature.end()) != buffer.end()) {
        cout << "[ALERT] Malicious signature found in " << filename << "!" << endl;
        return true;
    }

    cout << "[SAFE] No threat detected in " << filename << "." << endl;
    return false;
}

int main() {
    scanFile("example.exe"); // Replace with actual file path
    return 0;
}
