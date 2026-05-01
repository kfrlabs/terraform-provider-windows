# Import a rule in the default PersistentStore by its technical Name:
terraform import windows_firewall_rule.allow_https Allow-Inbound-HTTPS

# Import a rule from an explicit policy store (format: <policy_store>/<name>):
terraform import windows_firewall_rule.allow_https ActiveStore/Allow-Inbound-HTTPS
