# Test harness for the terraform-provider-windows acceptance suite.
#
# The image holds no credential: the `tfacc` account is created (or its
# password reset) at container start from the TFACC_PASSWORD environment
# variable, see set-tfacc-user.ps1. One image therefore serves any password,
# and rotating the lab secret no longer means rebuilding.
#
# Layers are ordered from least to most likely to change, so the PowerShell 7
# download is reused from the build cache when only the SSH configuration,
# the OpenSSH binaries or the scripts change.
FROM mcr.microsoft.com/windows/servercore:ltsc2025

SHELL ["powershell", "-NoProfile", "-Command", "$ErrorActionPreference='Stop';"]

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
# also proves pwsh.exe resolves via the system PATH, which is exactly how
# the provider will invoke it over SSH, and that the installed version
# matches the pin above.
RUN $v = & pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()' ; \
    if ($v -ne $env:POWERSHELL_VERSION) { throw "pwsh version mismatch: got $v, want $env:POWERSHELL_VERSION" } ; \
    Write-Host "pwsh $v ready"

# Minimal sshd_config written from scratch: the shipped default ends with a
# "Match Group administrators" block, so appended directives land inside that
# block and sshd refuses to start. SyslogFacility LOCAL0 enables file
# logging, so a failed start is diagnosable from docker exec.
RUN New-Item -ItemType Directory -Force -Path C:\ProgramData\ssh | Out-Null ; \
    Set-Content -Path C:\ProgramData\ssh\sshd_config -Encoding ascii -Value @( \
      'Port 22', \
      'PasswordAuthentication yes', \
      'PubkeyAuthentication yes', \
      'StrictModes no', \
      'LogLevel VERBOSE', \
      'SyslogFacility LOCAL0')

# OpenSSH binaries are copied from the host: same OS build, no download needed.
COPY OpenSSH C:/OpenSSH/
COPY set-tfacc-user.ps1 C:/set-tfacc-user.ps1
COPY entrypoint.cmd C:/entrypoint.cmd

# sshd needs SeTcbPrivilege for CreateProcessAsUserW; started as
# ContainerAdministrator it fails with error 1314 right after the handshake,
# and registering it as a service dies at 1067 before it can even log.
# Running the container process itself as SYSTEM is the simple way out, and it
# keeps sshd in the foreground so its log is the container log.
USER "NT AUTHORITY\SYSTEM"

EXPOSE 22
CMD ["cmd", "/c", "C:\\entrypoint.cmd"]
