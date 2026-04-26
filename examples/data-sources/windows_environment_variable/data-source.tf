# Look up an existing machine-scope environment variable.
data "windows_environment_variable" "java_home" {
  name  = "JAVA_HOME"
  scope = "machine"
}

output "java_home_value" {
  value = data.windows_environment_variable.java_home.value
}

# Look up a REG_EXPAND_SZ variable — value contains raw %VAR% tokens.
data "windows_environment_variable" "tools_dir" {
  name  = "TOOLS_DIR"
  scope = "machine"
}

output "tools_dir_is_expandable" {
  value = data.windows_environment_variable.tools_dir.expand
}
