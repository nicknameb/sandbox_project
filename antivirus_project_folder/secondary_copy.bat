@echo off
SET script_dir=%~dp0
copy "%script_dir%shared_vm_folder\secondary_container" "%script_dir%shared_vm_folder\shared_container"