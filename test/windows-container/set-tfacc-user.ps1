# Creates the local admin account the acceptance suite logs in as, or resets
# its password if it already exists. Run by entrypoint.cmd at every container
# start, and by `docker exec -e TFACC_PASSWORD` to rotate the password of a
# running container. The password must not contain the account name, and must
# stay under 15 characters to avoid the interactive net.exe prompt.
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($env:TFACC_PASSWORD)) {
    throw 'TFACC_PASSWORD is required (docker run -e TFACC_PASSWORD ...).'
}
$secure = ConvertTo-SecureString $env:TFACC_PASSWORD -AsPlainText -Force

if (Get-LocalUser -Name tfacc -ErrorAction SilentlyContinue) {
    Set-LocalUser -Name tfacc -Password $secure
} else {
    New-LocalUser -Name tfacc -Password $secure -PasswordNeverExpires -AccountNeverExpires | Out-Null
}
if (-not (Get-LocalGroupMember -Group Administrators -Member tfacc -ErrorAction SilentlyContinue)) {
    Add-LocalGroupMember -Group Administrators -Member tfacc
}
Write-Host 'tfacc account ready'
