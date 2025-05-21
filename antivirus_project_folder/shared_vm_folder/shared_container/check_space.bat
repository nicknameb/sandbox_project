@echo off
powershell.exe -NoProfile -Command "Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:'\" | Select-Object FreeSpace,Size"