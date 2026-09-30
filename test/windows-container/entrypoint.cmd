@echo off
REM Host keys are generated here, at runtime, rather than at build time: the
REM container process runs as SYSTEM, so the keys are created with an ACL that
REM Win32-OpenSSH accepts. Generating them during the build leaves a
REM "User Manager\ContainerAdministrator:(M)" ACE behind and sshd rejects them
REM with "permissions are too open".
if not exist C:\ProgramData\ssh\ssh_host_ed25519_key C:\OpenSSH\ssh-keygen.exe -A
C:\OpenSSH\sshd.exe -D -e
