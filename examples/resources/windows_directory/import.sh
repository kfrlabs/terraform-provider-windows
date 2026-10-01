# Import a directory by its absolute Windows path.
# ID format: <path>
# recursive_delete and create_parent_directories are not observable on the
# host and fall back to their schema defaults after import.
terraform import windows_directory.app_logs 'C:\ProgramData\app\logs'
