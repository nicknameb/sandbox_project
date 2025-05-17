#include <Windows.h>
#include <iostream> 
#include <cstdlib> 
#include "sandbox_vm.h"  
#include <chrono>
#include <fstream> 
using namespace std; 
using namespace std::chrono;

  

bool RunCommandVM(const string& vboxPath, const string& vmName, const string& command)
{  
    char path_buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path_buffer);
    string current_dir(path_buffer);
    string log_file = current_dir + "\\scan_output.txt";

    ofstream log(log_file, ios::app);

    STARTUPINFOA si_command = { sizeof(si_command) };
    PROCESS_INFORMATION pi_command;

    char cmdLine[512];  
    strncpy_s(cmdLine, command.c_str(), sizeof(cmdLine) - 1);

    BOOL success = CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si_command, &pi_command);
    SetPriorityClass(pi_command.hProcess, HIGH_PRIORITY_CLASS);
    if (!success)
    {
        log << "ERROR: failed to run command: " << command << endl;
        return false;
    }
    else
    {
        WaitForSingleObject(pi_command.hProcess, INFINITE);
        log << "VM ran command succefully: "<< command << endl;
        CloseHandle(pi_command.hProcess);
        CloseHandle(pi_command.hThread); 
        return true;
    }
} 


bool Sandbox_vm::RunVirtualBoxVM(const string& vboxPath, const string& vmName, const string& snapshotName, const string& hostfile_path, const string& guestfile_path, const string& username, const string& password) {
    char path_buffer[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, path_buffer);
    string current_dir(path_buffer);
    string log_file = current_dir + "\\scan_output.txt";

    ofstream log(log_file, ios::app);

    
    string check_login_command = "\"" + vboxPath + "\" guestcontrol \"" + vmName + "\" run " + "--username \"" + username + "\" " + "--password \"" + password + "\" " + "--timeout=10000 " + "--exe \"cmd.exe\" -- cmd.exe /c echo OK";

    string power_off_command = "\"" + vboxPath + "\" controlvm \"" + vmName + "\" poweroff"; 
    RunCommandVM(vboxPath, vmName, power_off_command);
    Sleep(10000);

    
    //restore snapshot
    string restore_snapshot_command = "\"" + vboxPath + "\" snapshot \"" + vmName + "\" restore \"" + snapshotName + "\"";
    RunCommandVM(vboxPath, vmName, restore_snapshot_command); 
    Sleep(30000);

    string discardCmd = "\"" + vboxPath + "\" discardstate \"" + vmName + "\"";
    RunCommandVM(vboxPath, vmName, discardCmd);
    Sleep(1000);

    string startCommand = "\"" + vboxPath + "\" startvm \"" + vmName + "\" --type headless";

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;

    BOOL success = CreateProcessA(NULL, (LPSTR)startCommand.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);  //vm is very slow otherwise, this location seems to be fine
    if (!success) {
        log << "ERROR: Failed to start VM Error: " << GetLastError() << endl;
        return false;
    }
    else
    { 
        log << "VM started" << endl;
    }

    Sleep(46000);

    const string take_shot_bat = guestfile_path + "take_shot.bat";


    log << "running regshot" << endl;

    string run_regshot_bat = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + take_shot_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + take_shot_bat + "\""; //"--verbose"

    auto start = high_resolution_clock::now();
    RunCommandVM(vboxPath, vmName, run_regshot_bat); 
    auto stop = high_resolution_clock::now();

    auto duration = duration_cast<seconds>(stop - start);

    log << "taking a snapshot took: " << duration.count() << "seconds" << endl;
    


    //transfer suspicious application to the vm 
    

    string copy_file_bat = guestfile_path + "copy_malware.bat";
    string copy_file_command = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + copy_file_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + copy_file_bat + "\"";
    
    log << "copying file" << endl;
    RunCommandVM(vboxPath, vmName, copy_file_command);
    Sleep(1000); 

    size_t pos = hostfile_path.find_last_of("\\/");  //get name of malware itself
    string app_name = hostfile_path.substr(pos + 1); 

    string malware_location = guestfile_path + app_name;  
    log << "running potential malware" << endl; //"--timeout 5000 --no-wait-stdout" 

    string powershellPath = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";

    string run_malware = "\"" + vboxPath + "\" guestcontrol \"" + vmName + "\" run " "--username \"" + username + "\" " "--password \"" + password + "\" " "--exe \"" + powershellPath + "\" -- \"" + powershellPath + "\" " "-NoProfile -WindowStyle Hidden " "-Command \"Start-Process -FilePath '" + malware_location + "' -WindowStyle Hidden\"";

    RunCommandVM(vboxPath, vmName, run_malware); 
    Sleep(3000);   

    

    const string compare_shot_bat = guestfile_path + "compare_shot.bat";
    const string run_compare_bat = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + compare_shot_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + compare_shot_bat + "\"";

    log << "comparing snaps" << endl;  

    start = high_resolution_clock::now();
    RunCommandVM(vboxPath, vmName, run_compare_bat); 
    stop = high_resolution_clock::now();
    duration = duration_cast<seconds>(stop - start); 
    log << "comparing a snapshot took: " << duration.count() << "seconds" << endl;
    
    string copy_result_bat = guestfile_path + "copy_result.bat";
    const string run_result_bat = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + copy_result_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + copy_result_bat + "\"";
    RunCommandVM(vboxPath, vmName, run_result_bat);
    Sleep(1000);
    

    RunCommandVM(vboxPath, vmName, power_off_command);
    Sleep(10000); 


    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}  
