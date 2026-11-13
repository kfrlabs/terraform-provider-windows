# Import a site by name. The live settings are adopted into state;
# unconfigured attributes reflect the observed values, and site_id stays
# managed (it is part of the identity). The bindings view is observed
# read-only (managed by windows_iis_binding).
terraform import windows_iis_site.web 'web'
