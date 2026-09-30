# windows_file is imported by absolute path.
#
# Files under 1 MiB have their content read back during the import, so the
# first plan is clean when your configuration matches what is already on the
# host. Above 1 MiB the content attribute stays empty and the first apply
# rewrites the file.
terraform import windows_file.web 'C:\inetpub\wwwroot\web.config'

# UNC paths work too, provided the SSH account can reach the share
# (a local account normally cannot: Kerberos double hop).
terraform import windows_file.shared '\\fileserver\deploy\app.ini'
