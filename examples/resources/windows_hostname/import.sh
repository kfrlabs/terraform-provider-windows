# Import an existing windows_hostname by the target machine's MachineGuid
# (HKLM:\SOFTWARE\Microsoft\Cryptography\MachineGuid). The hostname itself
# is NOT a stable identifier — the resource ID is anchored on MachineGuid so
# that renames don't break state and machine replacement is detected.
terraform import windows_hostname.this 11111111-2222-3333-4444-555555555555
