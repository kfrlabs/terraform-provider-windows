# Import a machine-scope environment variable.
# ID format: <scope>:<name>
terraform import windows_environment_variable.java_home 'machine:JAVA_HOME'

# Import a user-scope environment variable.
terraform import windows_environment_variable.my_token 'user:MY_APP_TOKEN'
