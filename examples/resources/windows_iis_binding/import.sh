# Import a binding by <site>|<protocol>|<bindingInformation>. The live
# certificate/SNI pair is adopted into state; unconfigured in-place
# attributes reflect the observed values.
terraform import windows_iis_binding.https 'web|https|*:443:example.com'
