# Throwaway Windows container for acceptance tests

A disposable SSH-reachable Windows target for `make testacc`, when you have a
Windows Server host with Docker but do not want the suite writing to it
directly. Everything the tests create lands inside the container and disappears
with it.

This is a **local test fixture**, not something to expose: the account is a
throwaway local admin, `StrictModes` is off, and the default password below is
public. Run it on a trusted network and delete it afterwards.

## Requirements

- A Windows Server host (validated on **Server 2025**) with Docker Engine in
  **process isolation** mode.
- The base image tag must match the host build: `servercore:ltsc2025` on
  Server 2025. Process isolation refuses a mismatched kernel.
- OpenSSH Server present on the host at `C:\Windows\System32\OpenSSH`. Its
  binaries are copied into the image, so no download is needed and the version
  is guaranteed compatible with the kernel.

## Build and run

On the Windows host:

```powershell
# Build context: this directory + the host's OpenSSH binaries.
mkdir C:\tfacc
Copy-Item -Recurse C:\Windows\System32\OpenSSH C:\tfacc\OpenSSH
# copy Dockerfile and entrypoint.cmd from this directory into C:\tfacc

cd C:\tfacc
docker build -t tfacc-win:latest .
docker run -d --name tfacc-win -p 2222:22 tfacc-win:latest

# Only if the host firewall blocks the published port.
New-NetFirewallRule -DisplayName tfacc-ssh -Direction Inbound `
  -Protocol TCP -LocalPort 2222 -Action Allow
```

Override the password with `--build-arg TFACC_PASSWORD=...`. It must not
contain the account name `tfacc` and must stay under 15 characters, see below.

## Run the suite against it

From the repository root, on any machine that can reach the published port:

```bash
export TF_ACC=1
export WINDOWS_HOST=<host>
export WINDOWS_PORT=2222
export WINDOWS_USERNAME=tfacc
export WINDOWS_PASSWORD='Zx9-Terra!2026'
export WINDOWS_INSECURE_IGNORE_HOST_KEY=true

go test -tags acceptance ./internal/provider/ -run TestAccWindowsFile -v -timeout 35m
```

`terraform` must be on `PATH`, or point `TF_ACC_TERRAFORM_PATH` at a binary.

## Teardown

```powershell
docker rm -f tfacc-win
Remove-NetFirewallRule -DisplayName tfacc-ssh
Remove-Item -Recurse -Force C:\tfacc
```

## Four traps this image exists to encode

Each one costs a build-and-debug cycle to rediscover, and none produces an
obvious error message.

1. **`net user` blocks on a password of 15+ characters**, and rejects any
   password containing the account name. It prompts interactively, so the build
   hangs instead of failing. `New-LocalUser` is used here, and the password
   constraint still applies.

2. **sshd must run as SYSTEM.** Started as `ContainerAdministrator` it
   authenticates fine, then kills the session immediately with
   `CreateProcessAsUserW failed error:1314` — `SeTcbPrivilege` is missing.
   Hence `USER "NT AUTHORITY\SYSTEM"`. Registering sshd as a Windows service is
   the other textbook answer and it does *not* work here either: the service
   dies with error 1067 before writing a single log line.

3. **Host keys must be generated at runtime, not at build time.** Generated
   during the build they keep a `User Manager\ContainerAdministrator:(M)` ACE
   and sshd refuses them with "permissions are too open". `StrictModes no` does
   not cover host keys. `entrypoint.cmd` generates them on first start, as
   SYSTEM, so the ACL is right by construction.

4. **`sshd_config` is written from scratch.** The shipped
   `sshd_config_default` ends with a `Match Group administrators` block, so any
   appended global directive silently lands *inside* that block and sshd
   refuses to start.

A fifth, unrelated to this image but hit through it: Windows Server 2025 base
images already register an `sshd` service, so `sc create sshd` fails with
"service already exists".
