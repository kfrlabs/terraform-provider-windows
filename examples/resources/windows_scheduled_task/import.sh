# Import a scheduled task by its composite ID: <TaskPath><TaskName>
# Root folder task:
terraform import windows_scheduled_task.backup '\Daily-Backup'

# Sub-folder task (folder path ends with backslash, task name follows):
terraform import windows_scheduled_task.reports '\Company\Finance\Weekly-Reports'
