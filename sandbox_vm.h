#pragma once 

#include <Windows.h> 
#include <iostream> 

using namespace std; 

class Sandbox_vm {  
public: 
	bool RunVirtualBoxVM(const string& vboxPath, const string& vmName, const string& snapshotName, const string& hostfile_path, const string& guestfile_path, const string& username, const string& password);

};

