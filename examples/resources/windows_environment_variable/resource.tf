# Machine-scope plain string (REG_SZ) — requires Local Administrator on target.
resource "windows_environment_variable" "java_home" {
  name  = "JAVA_HOME"
  value = "C:\\Program Files\\Java\\jdk-17"
  scope = "machine"

  # Bound every remote operation explicitly: without this block each
  # operation defaults to 10 minutes, and a stalled variable operation
  # (registry write, WM_SETTINGCHANGE broadcast) surfaces a timeout
  # diagnostic instead of blocking Terraform indefinitely.
  timeouts = {
    create = "20m"
    read   = "5m"
    update = "20m"
    delete = "20m"
  }
}

# Machine-scope expandable string (REG_EXPAND_SZ).
# Windows expands %VAR% tokens when applications call ExpandEnvironmentStrings.
resource "windows_environment_variable" "tools_dir" {
  name   = "TOOLS_DIR"
  value  = "%ProgramFiles%\\MyTools"
  scope  = "machine"
  expand = true
}

# User-scope variable — no elevated privileges required.
resource "windows_environment_variable" "my_token" {
  name  = "MY_APP_TOKEN"
  value = "abc123"
  scope = "user"
}
