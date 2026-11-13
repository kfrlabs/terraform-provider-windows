# Import an existing partition by its "<disk_unique_id>|<guid_or_offset>" ID
# (the GUID on GPT disks, the byte offset on MBR disks).
terraform import windows_partition.data 'SCSI\DISK&VEN_MSFT&PROD_VIRTUAL_DISK&REV_1.0|EBD0A0A2-B9E5-4433-87C0-68B6B72699C7'
