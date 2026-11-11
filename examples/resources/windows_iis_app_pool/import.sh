# Import an application pool by name. The live settings are adopted into
# state; unconfigured attributes reflect the observed values, and
# recycling_schedule starts unmanaged (null) until declared.
#
# The SpecificUser password cannot be imported: after import, set
# identity_password_wo together with a fresh identity_password_wo_version
# before the next apply when the pool uses a SpecificUser identity.
terraform import windows_iis_app_pool.api 'api'
