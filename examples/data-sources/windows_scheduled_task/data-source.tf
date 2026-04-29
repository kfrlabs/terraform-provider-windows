# Read an existing built-in scheduled task (read-only, no lifecycle management).
data "windows_scheduled_task" "defrag" {
  name = "ScheduledDefrag"
  path = "\\Microsoft\\Windows\\Defrag\\"
}

output "defrag_enabled" {
  value = data.windows_scheduled_task.defrag.enabled
}

output "defrag_state" {
  value = data.windows_scheduled_task.defrag.state
}

output "defrag_last_run" {
  value = data.windows_scheduled_task.defrag.last_run_time
}

# Read a task created by a resource in the same configuration.
data "windows_scheduled_task" "backup_info" {
  name = windows_scheduled_task.backup.name
  path = windows_scheduled_task.backup.path
}
