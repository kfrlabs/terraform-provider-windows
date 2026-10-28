<#
.SYNOPSIS
  Runs acceptance test groups as concurrent lanes against one Windows target.

.DESCRIPTION
  The acceptance suite has no t.Parallel(), so a single `go test` run executes
  every test back to back. Lanes run concurrently, but only use more than one
  where the machine has room: on a 4-vCPU windows-latest runner, where the
  target is the runner itself, concurrent families were CPU/memory bound
  (2-3x slower each, then out of memory), so testacc-windows.yml runs one
  lane per runner. The script still gives every job the same group
  definitions, failure annotations and step summary.

  Groups are defined in .github/testacc-groups.json. -Lanes is a
  whitespace-separated list of lanes; each lane runs in its own test process,
  concurrently with the others. Groups joined with '+' share one lane and run
  sequentially, which is how machine-global work (DISM / windows_feature) is
  kept from overlapping with itself.

  The test binary is compiled once (`go test -c`) and started once per lane.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$Binary,
    [string]$Lanes = '',
    # Overrides -Lanes: a single lane running this `-run` regexp, no skip.
    [string]$RunFilter = '',
    [string]$GroupsFile = (Join-Path $PSScriptRoot '..\testacc-groups.json'),
    [string]$WorkingDirectory = (Get-Location).Path,
    [string]$Timeout = '30m',
    [string]$LogDirectory = (Join-Path ([IO.Path]::GetTempPath()) 'testacc-logs'),
    [int]$HeartbeatSeconds = 60,
    # Heading for the GitHub step summary table.
    [string]$Title = 'Acceptance lanes'
)

$ErrorActionPreference = 'Stop'

$groups = (Get-Content -Raw -Path $GroupsFile | ConvertFrom-Json).groups
$byName = @{}
foreach ($g in $groups) { $byName[$g.name] = $g }

$plan = @()
if ($RunFilter) {
    $plan += [pscustomobject]@{ Name = 'run_filter'; Run = $RunFilter; Skip = '' }
} else {
    foreach ($lane in ($Lanes -split '\s+' | Where-Object { $_ })) {
        $names = @($lane -split '\+')
        $runs = @()
        $catchAll = $false
        foreach ($n in $names) {
            $g = $byName[$n]
            if (-not $g) { throw "unknown test group '$n' (see $GroupsFile)" }
            if ($g.catchAll) { $catchAll = $true }
            $runs += "($($g.run))"
        }
        $skip = ''
        if ($catchAll) {
            # The catch-all matches every test, so a lane holding it is
            # expressed as a skip instead: every test claimed by a group that
            # is not in this lane. Empty when the lane holds every group.
            $skip = (@($groups | Where-Object { -not $_.catchAll -and $names -notcontains $_.name } | ForEach-Object { "($($_.run))" })) -join '|'
        }
        $plan += [pscustomobject]@{ Name = $lane; Run = ($runs -join '|'); Skip = $skip }
    }
}
if (-not $plan) { throw 'no lanes to run: pass -Lanes or -RunFilter' }

$Binary = (Resolve-Path $Binary).Path
New-Item -ItemType Directory -Force -Path $LogDirectory | Out-Null

$running = foreach ($lane in $plan) {
    $base = Join-Path $LogDirectory ($lane.Name -replace '[^\w.-]', '_')
    $argv = @('-test.v', '-test.timeout', $Timeout, '-test.run', $lane.Run)
    if ($lane.Skip) { $argv += @('-test.skip', $lane.Skip) }
    Write-Host "lane $($lane.Name): -run $($lane.Run)$(if ($lane.Skip) { " -skip $($lane.Skip)" })"
    $p = Start-Process -FilePath $Binary -ArgumentList ($argv | ForEach-Object { '"' + $_ + '"' }) `
        -WorkingDirectory $WorkingDirectory -NoNewWindow -PassThru `
        -RedirectStandardOutput "$base.out.log" -RedirectStandardError "$base.err.log"
    # Without touching Handle, Process.ExitCode can come back null once the
    # process has exited.
    $null = $p.Handle
    [pscustomobject]@{ Lane = $lane; Proc = $p; Out = "$base.out.log"; Err = "$base.err.log"; Start = Get-Date; End = $null }
}

$sw = [Diagnostics.Stopwatch]::StartNew()
while ($true) {
    foreach ($r in $running) { if (-not $r.End -and $r.Proc.HasExited) { $r.End = Get-Date } }
    $pending = @($running | Where-Object { -not $_.End })
    if (-not $pending) { break }
    if ($sw.Elapsed.TotalSeconds -ge $HeartbeatSeconds) {
        $sw.Restart()
        $done = @($running | ForEach-Object { (Select-String -Path $_.Out -Pattern '^\s*--- (PASS|FAIL|SKIP):' -ErrorAction SilentlyContinue).Count } | Measure-Object -Sum).Sum
        Write-Host ("[{0:hh\:mm\:ss}] {1} test(s) finished, still running: {2}" -f ((Get-Date) - $running[0].Start), $done, (($pending | ForEach-Object { $_.Lane.Name }) -join ', '))
    }
    Start-Sleep -Seconds 2
}

$failed = $false
$summary = @('| lane | result | duration | pass | fail | skip | slowest |', '|---|---|---|---|---|---|---|')
foreach ($r in $running) {
    $r.Proc.WaitForExit()
    $code = $r.Proc.ExitCode
    $dur = $r.End - $r.Start
    $lines = @(Get-Content -Path $r.Out -ErrorAction SilentlyContinue)
    $results = @($lines | Select-String -Pattern '^--- (PASS|FAIL|SKIP): (\S+) \(([\d.]+)s\)' | ForEach-Object {
            [pscustomobject]@{ Status = $_.Matches[0].Groups[1].Value; Name = $_.Matches[0].Groups[2].Value; Seconds = [double]$_.Matches[0].Groups[3].Value }
        })
    $count = { param($s) @($results | Where-Object Status -EQ $s).Count }
    $slowest = (($results | Sort-Object Seconds -Descending | Select-Object -First 3 | ForEach-Object { "$($_.Name) $([math]::Round($_.Seconds))s" }) -join ', ')

    Write-Host ("::group::lane {0}: exit {1} in {2:mm\:ss}" -f $r.Lane.Name, $code, $dur)
    $lines | Write-Host
    Get-Content -Path $r.Err -ErrorAction SilentlyContinue | Write-Host
    Write-Host '::endgroup::'

    if ($code -ne 0) {
        $failed = $true
        $failures = @($results | Where-Object Status -EQ 'FAIL' | ForEach-Object Name)
        $what = if ($failures) { $failures -join ', ' } else { 'no --- FAIL line: build error, panic or timeout, see the lane log' }
        Write-Host "::error title=acceptance lane $($r.Lane.Name) failed::exit $code; $what"
    }
    $summary += ('| {0} | {1} | {2:mm\:ss} | {3} | {4} | {5} | {6} |' -f $r.Lane.Name, $(if ($code -eq 0) { 'ok' } else { "exit $code" }), $dur, (& $count 'PASS'), (& $count 'FAIL'), (& $count 'SKIP'), $slowest)
}

$summary | Write-Host
if ($env:GITHUB_STEP_SUMMARY) {
    (@("### $Title", '') + $summary + '') | Out-File -FilePath $env:GITHUB_STEP_SUMMARY -Append -Encoding utf8
}
# Explicit in both cases: callers read $LASTEXITCODE, which a script that
# just falls off the end leaves at whatever the previous command set.
if ($failed) { exit 1 }
exit 0
