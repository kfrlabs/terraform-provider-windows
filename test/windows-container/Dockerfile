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

# PowerShell 7: the provider prefers a persistent pwsh.exe session and only
# falls back to one powershell.exe (5.1) process per call without it (see
# ADR-0010). ServerCore ships 5.1 only, so install PS7 here; without this
# the lab exercises the slow fallback path instead of the persistent
# transport under test.
ARG POWERSHELL_VERSION='7.4.6'
RUN $msi = Join-Path $env:TEMP 'PowerShell-win-x64.msi' ; \
    Invoke-WebRequest -Uri ('https://github.com/PowerShell/PowerShell/releases/download/v{0}/PowerShell-{0}-win-x64.msi' -f $env:POWERSHELL_VERSION) -OutFile $msi -UseBasicParsing ; \
    $p = Start-Process msiexec.exe -ArgumentList @('/package', $msi, '/quiet', '/norestart', 'ADD_EXPLORER_CONTEXT_MENU_OPENPOWERSHELL=0', 'ADD_FILE_CONTEXT_MENU_RUNPOWERSHELL=0', 'ENABLE_PSREMOTING=0', 'REGISTER_MANIFEST=0') -Wait -PassThru ; \
    if ($p.ExitCode -ne 0 -and $p.ExitCode -ne 3010) { throw "pwsh msiexec failed: $($p.ExitCode)" } ; \
    Remove-Item $msi -Force

# Separate layer on purpose: it starts with a fresh environment, so this
# also proves pwsh.exe resolves via the system PATH — which is exactly how
# the provider will invoke it over SSH — and that the installed version
# matches the pin above.
RUN $v = & pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' ; \
    if ($v -ne $env:POWERSHELL_VERSION) { throw "pwsh version mismatch: got $v, want $env:POWERSHELL_VERSION" } ; \
    Write-Host "pwsh $v ready"

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
