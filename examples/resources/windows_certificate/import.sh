# Import an existing certificate by <store_location>/<store_name>/<thumbprint>.
# A certificate carrying a private key is assumed PFX-backed and imports with
# pfx_wo_version = 1: add the bundle and password back in configuration before
# the next apply. A keyless certificate imports with its normalised PEM in
# certificate_pem.
# Note: import always sets exportable = false in state. If the private key was
# imported as exportable, set exportable = true in configuration before the
# first apply so the plan matches the host (exportable forces replacement).
terraform import windows_certificate.web "LocalMachine/My/A1B2C3D4E5F60718293A4B5C6D7E8F9012345678"
