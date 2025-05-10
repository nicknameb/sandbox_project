#include <Windows.h>
#include <iostream> 
#include <cstdlib> 
#include "sandbox_vm.h" 

using namespace std; 

bool RunCommandVM(const string& vboxPath, const string& vmName, const string& command)
{
    STARTUPINFOA si_command = { sizeof(si_command) };
    PROCESS_INFORMATION pi_command;

    char cmdLine[512];  
    strncpy_s(cmdLine, command.c_str(), sizeof(cmdLine) - 1);

    BOOL success = CreateProcessA(NULL, cmdLine, NULL, NULL, FALSE, 0, NULL, NULL, &si_command, &pi_command);
    SetPriorityClass(pi_command.hProcess, HIGH_PRIORITY_CLASS);
    if (!success)
    {
        cout << "[ERROR] failed to run command: " << command << endl;  
        return false;
    }
    else
    {
        WaitForSingleObject(pi_command.hProcess, INFINITE);
        cout << "VM ran command succefully: "<< command << endl;
        CloseHandle(pi_command.hProcess);
        CloseHandle(pi_command.hThread); 
        return true;
    }
} 


bool Sandbox_vm::RunVirtualBoxVM(const string& vboxPath, const string& vmName, const string& snapshotName, const string& hostfile_path, const string& guestfile_path) {
    //make sure VM is powred off  
    const string username = "JACOB";
    const string password = "ahiadel68410";
    string check_login_command = "\"" + vboxPath + "\" guestcontrol \"" + vmName + "\" run " + "--username \"" + username + "\" " + "--password \"" + password + "\" " + "--timeout=10000 " + "--exe \"cmd.exe\" -- cmd.exe /c echo OK";

    string power_off_command = "\"" + vboxPath + "\" controlvm \"" + vmName + "\" poweroff"; 
    RunCommandVM(vboxPath, vmName, power_off_command);
    Sleep(10000);

   

    //restore snapshot
    string restore_snapshot_command = "\"" + vboxPath + "\" snapshot \"" + vmName + "\" restore \"" + snapshotName + "\"";
    RunCommandVM(vboxPath, vmName, restore_snapshot_command); 
    Sleep(40000);

    //string read_vm_state = "\"" + vboxPath + "\" showvminfo \"" + vmName + "\" --machinereadable"; 



    //start the vm
    string startCommand = "\"" + vboxPath + "\" startvm \"" + vmName + "\" --type headless";

    STARTUPINFOA si = { sizeof(STARTUPINFOA) };
    PROCESS_INFORMATION pi;

    BOOL success = CreateProcessA(NULL, (LPSTR)startCommand.c_str(), NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi);
    SetPriorityClass(pi.hProcess, HIGH_PRIORITY_CLASS);  //vm is very slow otherwise, this location seems to be fine
    if (!success) {
        cerr << "[ERROR] Failed to start VM Error: " << GetLastError() << endl;
        return false;
    }
    

    Sleep(36000);


     

    //check if user can login  
    bool valid_login = RunCommandVM(vboxPath, vmName, check_login_command); 
    Sleep(20000);
    if (valid_login)
    { 
        cout << "can login to VM" << endl;
    }  
    else
    { 
        cout << "[ERROR] failed to login" << endl;
    }
    //string waitForGuestReady = "\"" + vboxPath + "\" guestproperty wait \"" + vmName + "\" \"/VirtualBox/GuestInfo/OS/LoggedInUsers\"" + "--timeout=60000 ";

    


    //create bat file, copy into folder on the vm, run from there
    const string cwd = "C:\\Users\\jacob\\Downloads\\Regshot_folder";
    const string regshotPath = "C:\\Users\\jacob\\Downloads\\Regshot_folder\\Regshot_cmd-x64-ANSI.exe";
    const string regshot_original = "C:\\Users\\jacob\\Downloads\\reg1.hivu -C"; 
    const string regshot_output = "C:\\Users\\jacob\\Downloads\\Regshot_folder\\~res-x64.txt";

    const string take_shot_bat = "C:\\Users\\jacob\\Downloads\\Regshot_folder\\take_shot.bat";

    cout << "running regshot" << endl;
    string run_regshot_bat = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + take_shot_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + take_shot_bat + "\""; //"--verbose"
    RunCommandVM(vboxPath, vmName, run_regshot_bat);

    Sleep(30000);


    //transfer suspicious application to the vm 
    

    string copy_file_bat = "C:\\Users\\jacob\\Downloads\\Regshot_folder\\copy_malware.bat"; 
    string copy_file_command = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + copy_file_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + copy_file_bat + "\"";
    
    cout << "copying file" << endl;
    RunCommandVM(vboxPath, vmName, copy_file_command);
    Sleep(5000); 

    size_t pos = hostfile_path.find_last_of("\\/");  //get name of malware itself
    string app_name = hostfile_path.substr(pos + 1); 

    string malware_location = guestfile_path + app_name; 
    string run_malware = "\"" + vboxPath + "\" guestcontrol \"" + vmName + "\" run " +"--username \"" + username + "\" " +"--password \"" + password + "\" " +"--exe \"" + malware_location + "\" " +"-- \"" + malware_location + "\"" " --verbose";
    RunCommandVM(vboxPath, vmName, run_malware); 

    Sleep(5000); 
 
    const string compare_shot_bat = "C:\\Users\\jacob\\Downloads\\Regshot_folder\\compare_shot.bat"; 
    const string run_compare_bat = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + compare_shot_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + compare_shot_bat + "\"";

    cout << "comparing snaps" << endl;
    RunCommandVM(vboxPath, vmName, run_compare_bat);
    //Sleep(30000);
    
    string copy_result_bat = "C:\\Users\\jacob\\Downloads\\Regshot_folder\\copy_result.bat";
    const string run_result_bat = vboxPath + " guestcontrol \"" + vmName + "\" run --exe \"" + copy_result_bat + "\" --username \"" + username + "\" --password \"" + password + "\" -- \"" + copy_result_bat + "\"";
    RunCommandVM(vboxPath, vmName, run_result_bat);
    Sleep(1000);
    

    RunCommandVM(vboxPath, vmName, power_off_command);
    Sleep(10000); 


    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}  

//when reg3 doesnt exist yet:

//Regshot_cmd-x64-ANSI.exe C:\Users\jacob\Downloads\reg3.hivu  
//run by running "C:\Users\jacob\Downloads\Regshot_folder\take_shot.bat"

//Regshot_cmd-x64-ANSI.exe C:\Users\jacob\Downloads\reg3.hivu -C  
//run by running "C:\Users\jacob\Downloads\Regshot_folder\compare_shot.bat"

//result will be stored in  "C:\Users\jacob\Downloads\Regshot_folder\~res-x64.txt" 



//copy file: "C:\Users\jacob\Downloads\Regshot_folder\copy_malware.bat" 
//from: "Z:\test_folder" 
//to "C:\Users\jacob\Downloads\malware_folder" 
//ready made snapshot: "C:\Users\jacob\Downloads\reg4.hivu" 

//notepad path: "C:\Program Files\WindowsApps\Microsoft.WindowsNotepad_11.2501.31.0_x64__8wekyb3d8bbwe\Notepad\Notepad.exe" 



//path to copy_result.bat = "C:\Users\jacob\Downloads\Regshot_folder\copy_result.bat"