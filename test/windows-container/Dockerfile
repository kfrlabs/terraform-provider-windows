# Test harness for the terraform-provider-windows acceptance suite.
# OpenSSH binaries are copied from the host: same OS build, no download needed.
FROM mcr.microsoft.com/windows/servercore:ltsc2025

COPY OpenSSH C:/OpenSSH/
COPY entrypoint.cmd C:/entrypoint.cmd

SHELL ["powershell", "-NoProfile", "-Command", "$ErrorActionPreference='Stop';"]

# Local admin account used by the provider over SSH. The password must not
# contain the account name, and must stay under 15 characters to avoid the
# interactive net.exe prompt.
ARG TFACC_PASSWORD='Zx9-Terra!2026'

RUN $p = ConvertTo-SecureString $env:TFACC_PASSWORD -AsPlainText -Force ; \
    New-LocalUser -Name tfacc -Password $p -PasswordNeverExpires -AccountNeverExpires | Out-Null ; \
    Add-LocalGroupMember -Group Administrators -Member tfacc

# Minimal sshd_config written from scratch: the shipped default ends with a
# "Match Group administrators" block, so appended directives land inside that
# block and sshd refuses to start.
RUN New-Item -ItemType Directory -Force -Path C:\ProgramData\ssh | Out-Null
RUN Set-Content -Path C:\ProgramData\ssh\sshd_config -Encoding ascii -Value 'Port 22'
RUN Add-Content -Path C:\ProgramData\ssh\sshd_config -Encoding ascii -Value 'PasswordAuthentication yes'
RUN Add-Content -Path C:\ProgramData\ssh\sshd_config -Encoding ascii -Value 'PubkeyAuthentication yes'
RUN Add-Content -Path C:\ProgramData\ssh\sshd_config -Encoding ascii -Value 'StrictModes no'
RUN Add-Content -Path C:\ProgramData\ssh\sshd_config -Encoding ascii -Value 'LogLevel VERBOSE'

# File logging, so a failed start is diagnosable from docker exec.
RUN Add-Content -Path C:\ProgramData\ssh\sshd_config -Encoding ascii -Value 'SyslogFacility LOCAL0'

# sshd needs SeTcbPrivilege for CreateProcessAsUserW; started as
# ContainerAdministrator it fails with error 1314 right after the handshake,
# and registering it as a service dies at 1067 before it can even log.
# Running the container process itself as SYSTEM is the simple way out, and it
# keeps sshd in the foreground so its log is the container log.
USER "NT AUTHORITY\SYSTEM"

EXPOSE 22
CMD ["cmd", "/c", "C:\\entrypoint.cmd"]
