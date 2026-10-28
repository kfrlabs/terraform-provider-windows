@echo off
REM The tfacc account is created at runtime from TFACC_PASSWORD, so the image
REM itself carries no credential. The variable is then cleared so the SSH
REM sessions that sshd spawns do not inherit it.
powershell -NoProfile -ExecutionPolicy Bypass -File C:\set-tfacc-user.ps1 || exit /b 1
set TFACC_PASSWORD=
REM Host keys are generated here, at runtime, rather than at build time: the
REM container process runs as SYSTEM, so the keys are created with an ACL that
REM Win32-OpenSSH accepts. Generating them during the build leaves a
REM "User Manager\ContainerAdministrator:(M)" ACE behind and sshd rejects them
REM with "permissions are too open".
if not exist C:\ProgramData\ssh\ssh_host_ed25519_key C:\OpenSSH\ssh-keygen.exe -A
C:\OpenSSH\sshd.exe -D -e
