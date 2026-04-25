#!/usr/bin/env sh
# Import a windows_local_user resource by SID or by SAM account name.
#
# The provider auto-detects the format of the import ID:
#   - Values starting with "S-" are treated as SID strings.
#   - All other values are treated as SAM account names.
#
# After a successful import the resource ID is always set to the user SID
# regardless of which path was used. The `password` attribute will be null;
# set it in HCL and run `terraform apply` before the next plan cycle.

# --- Import by SID (most stable: immune to renames) ---
terraform import windows_local_user.svc_backup S-1-5-21-1234567890-987654321-1122334455-1001

# --- Import by SAM account name ---
terraform import windows_local_user.svc_backup svc-backup
