# Import an event log by exact name (classic or modern channel — the "/"
# in a channel name is part of the name). Logs always exist, so import only
# adopts the live settings into state; nothing is created. The observed
# values become the snapshot for a later restore_on_destroy.
terraform import windows_eventlog.application 'Application'
terraform import windows_eventlog.powershell 'Microsoft-Windows-PowerShell/Operational'
