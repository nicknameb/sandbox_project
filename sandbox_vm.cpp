#include <Windows.h>
#include <iostream> 
#include <cstdlib> 
#include "sandbox_vm.h"  
#include <chrono>
#include <fstream>  
#include <sstream>
#include <cstdint> 
#include <algorithm>
using namespace std; 
using namespace  chrono;

 
uint64_t ExtractFreeBytes(const  string& output) {
    istringstream stream(output);
    string line;
    int lineCount = 0;

    while (getline(stream, line)) {
        // Trim the line
        line.erase(0, line.find_first_not_of(" \t\r\n"));
        line.erase(line.find_last_not_of(" \t\r\n") + 1);

        if (line.empty()) continue;

        lineCount++;
        if (lineCount <= 2) continue;  // Skip header lines

        istringstream linestream(line);
        string freeStr;

        linestream >> freeStr;
        if (freeStr.empty()) {
            cerr << "Failed to find FreeSpace value in line: [" << line << "]\n";
            return 0;
        }

        try {
            uint64_t result = stoull(freeStr);
            cout << "Parsed FreeSpace: " << result << "\n";
            return result;
        }
        catch (const exception& e) {
            cerr << "Conversion error: " << e.what() << " on value: " << freeStr << "\n";
            return 0;
        }
    }

    cerr << "No valid line found after headers.\n";
    return 0;
}

bool RunCommandVM(const string& vboxPath, const string& vmName, const string& command, bool is_space_command = false, const string& hostfile_path = "default.txt")
{  
    char path_buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path_buffer);
    string current_dir(path_buffer);
    string log_file = current_dir + "\\scan_output.txt";

    ofstream log(log_file, ios::app);

    HANDLE hRead, hWrite;
    SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    CreatePipe(&hRead, &hWrite, &sa, 0);

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };   //capture output with pipeline
    PROCESS_INFORMATION pi;
    si.dwFlags |= STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = NULL;

    char cmdLine[512];  
    strncpy_s(cmdLine, command.c_str(), sizeof(cmdLine) - 1);

    BOOL success = CreateProcessA(NULL, cmdLine, NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi);
    SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);
    if (!success)
    { 
        CloseHandle(hWrite);
        CloseHandle(hRead);
        log << "ERROR: failed to run command: " << command << endl;
        return false;
    } 
    else
    { 
        CloseHandle(hWrite); 

        char buffer[4096];
        DWORD bytesRead;
        string output; 

        while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            output += buffer;
        } 

        CloseHandle(hRead); 

        WaitForSingleObject(pi.hProcess, INFINITE);
        log << "VM ran command succefully: "<< command << endl;
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);  

        if (is_space_command) //the command is to check how much space there is
        {  
            uint64_t free_bytes = ExtractFreeBytes(output); 
            if (free_bytes == 0)
            { 
                log << "ERROR: did not find free bytes" << endl;  
                log << output << endl;
                return 0;
            }  

            ifstream file(hostfile_path, ifstream::ate | ifstream::binary); //get file size of app to scan
            uint64_t file_size = static_cast<uint64_t>(file.tellg());  

            if (file_size > (free_bytes / 2))  //not enough free space in vm
            { 
                log << "ERROR: not enough free space in the vm" << endl;  
                log << output << endl;
                return false;
            }
            
        } 

        log << output << endl;
        return true;
    }
} 


bool Sandbox_vm::RunVirtualBoxVM(const string& vboxPath, const string& vmName, const string& snapshotName, const string& hostfile_path, const string& guestfile_path, const string& username, const string& password) {
    char path_buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path_buffer);
    string current_dir(path_buffer);
    string log_file = current_dir + "\\scan_output.txt";

    ofstream log(log_file, ios::app); 

    string powershellPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";


    //make sure the vm is powered off
    string power_off_command = "\"" + vboxPath + "\" controlvm \"" + vmName + "\" poweroff"; 
    RunCommandVM(vboxPath, vmName, power_off_command);
    Sleep(10000);

    
    //restore snapshot
    string restore_snapshot_command = "\"" + vboxPath + "\" snapshot \"" + vmName + "\" restore \"" + snapshotName + "\"";
    RunCommandVM(vboxPath, vmName, restore_snapshot_command); 
    Sleep(25000);

    //discard saved state if thers any, to prevent lock
    string discardCmd = "\"" + vboxPath + "\" discardstate \"" + vmName + "\"";
    RunCommandVM(vboxPath, vmName, discardCmd);
    Sleep(1000);

    string startCommand = "\"" + vboxPath + "\" startvm \"" + vmName + "\" --type headless";

    HANDLE hRead_start, hWrite_start;   //prevent terminal opening
    SECURITY_ATTRIBUTES sa_start = { sizeof(SECURITY_ATTRIBUTES), NULL, TRUE };
    CreatePipe(&hRead_start, &hWrite_start, &sa_start, 0);

    STARTUPINFOA si_start = { sizeof(STARTUPINFOA) };   
    PROCESS_INFORMATION pi_start;
    si_start.dwFlags |= STARTF_USESTDHANDLES;
    si_start.hStdOutput = hWrite_start;
    si_start.hStdError = hWrite_start;
    si_start.hStdInput = NULL;

    BOOL success = CreateProcessA(NULL, (LPSTR)startCommand.c_str(), NULL, NULL, TRUE, 0, NULL, NULL, &si_start, &pi_start);
    SetPriorityClass(pi_start.hProcess, HIGH_PRIORITY_CLASS);  //vm is very slow otherwise, this location seems to be fine
    if (!success) { 
        CloseHandle(hWrite_start);
        CloseHandle(hRead_start);
        log << "ERROR: Failed to start VM Error: " << GetLastError() << endl;
        return false;
    }
    else
    {  
        CloseHandle(hWrite_start);

        char buffer[4096];
        DWORD bytesRead;
        string vm_launch_output;

        while (ReadFile(hRead_start, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            vm_launch_output += buffer;
        }

        CloseHandle(hRead_start);
        log << vm_launch_output << endl;
    }

    Sleep(35000); 

    string copy_file_bat = guestfile_path + "copy_malware.bat";
    string copy_file_command = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + copy_file_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + copy_file_bat + "\""; 
    RunCommandVM(vboxPath, vmName, copy_file_command); 

    string check_space_bat = guestfile_path + "check_space.bat";
    string check_space_command = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + check_space_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + check_space_bat + "\"";
    
    bool enough_space  = RunCommandVM(vboxPath, vmName, check_space_command, true, hostfile_path); 
    if (!enough_space)
    {  
        log << "failed to run file in vm, not enough space" << endl;
        return false; 
    }


    // run bat file to run regshot and take a snapshot of the registry
    const string take_shot_bat = guestfile_path + "take_shot.bat";

    log << "running regshot" << endl;

    string run_regshot_bat = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + take_shot_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + take_shot_bat + "\""; //"--verbose"

    auto start = high_resolution_clock::now();
    RunCommandVM(vboxPath, vmName, run_regshot_bat); 
    auto stop = high_resolution_clock::now();

    auto duration = duration_cast<seconds>(stop - start);

    log << "taking a snapshot took: " << duration.count() << "seconds" << endl;
    


    
    
    //copy app to shared folder
    string secondary_copy_bat = hostfile_path + "secondary_copy.bat"; 
    string secondary_copy_command = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + secondary_copy_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + secondary_copy_bat + "\"";
    RunCommandVM(vboxPath, vmName, secondary_copy_bat); 
    Sleep(1000);

    //copy from shared folder to vm
    log << "copying file" << endl;
    RunCommandVM(vboxPath, vmName, copy_file_command);
    Sleep(1000); 


    //run the potential malware inside the vm
    size_t pos = hostfile_path.find_last_of("\\/");  //get name of malware itself
    string app_name = hostfile_path.substr(pos + 1); 

    string malware_location = guestfile_path + app_name;  
    log << "running potential malware" << endl;  


    string run_malware = "\"" + vboxPath + "\" guestcontrol \"" + vmName + "\" run " "--username \"" + username + "\" " "--password \"" + password + "\" " "--exe \"" + powershellPath + "\" -- \"" + powershellPath + "\" " "-NoProfile -WindowStyle Hidden " "-Command \"Start-Process -FilePath '" + malware_location + "' -WindowStyle Hidden\"";

    RunCommandVM(vboxPath, vmName, run_malware); 
    Sleep(3000);   

    string network_scan_path = guestfile_path + "network_scan.exe";
    string run_network_scan = "\"" + vboxPath + "\" guestcontrol \"" + vmName + "\" run " "--username \"" + username + "\" " "--password \"" + password + "\" " "--exe \"" + network_scan_path + "\" -- " "\"" + app_name +  "\"";

    RunCommandVM(vboxPath, vmName, run_network_scan);

    Sleep(3000);
    
    
    //take another snapshot
    const string compare_shot_bat = guestfile_path + "compare_shot.bat";
    const string run_compare_bat = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + compare_shot_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + compare_shot_bat + "\"";

    log << "comparing snaps" << endl;  

    start = high_resolution_clock::now();
    RunCommandVM(vboxPath, vmName, run_compare_bat); 
    stop = high_resolution_clock::now();
    duration = duration_cast<seconds>(stop - start); 
    log << "comparing a snapshot took: " << duration.count() << "seconds" << endl;
    
    //copy result over to shared file
    string copy_result_bat = guestfile_path + "copy_result.bat";
    const string run_result_bat = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + copy_result_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + copy_result_bat + "\"";
    RunCommandVM(vboxPath, vmName, run_result_bat);
    Sleep(1000);
    

    RunCommandVM(vboxPath, vmName, power_off_command);
    Sleep(10000); 


    CloseHandle(pi_start.hProcess);
    CloseHandle(pi_start.hThread);
    return true;
}  
