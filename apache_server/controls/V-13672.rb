# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13672 - The private web server must use an approved DoD certificate validation process.'
control 'V-13672' do
  impact 0.5
  title 'The private web server must use an approved DoD certificate validation process.'
  desc 'Without the use of a certificate validation process, the site is vulnerable to accepting certificates that have expired or have been revoked.  This would allow unauthorized individuals access to the web server.  This also defeats the purpose of the multi-factor authentication provided by the PKI process. '
  tag 'stig', 'V-13672'
  tag severity: 'medium'
  tag checkid: 'C-33636r2_chk'
  tag fixid: 'F-29277r2_fix'
  tag version: 'WG145 A22'
  tag ruleid: 'SV-32954r2_rule'
  tag fixtext: 'Configure DoD Private Web Servers to conduct certificate revocation checking utilizing certificate revocation lists (CRLs) or Online Certificate Status Protocol (OCSP).'
  tag checktext: 'The reviewer should query the ISSO, the SA, the web administrator, or developers as necessary to determine if the web server is configured to utilize an approved DoD certificate validation process.

The web administrator should be questioned to determine if a validation process is being utilized on the web server.

To validate this, the reviewer can ask the web administrator to describe the validation process being used. They should be able to identify either the use of certificate revocation lists (CRLs) or Online Certificate Status Protocol (OCSP).

If the production web server is accessible, the SA or the web administrator should be able to demonstrate the validation of good certificates and the rejection of bad certificates.

If CRLs are being used, the SA should be able to identify how often the CRL is updated and the location from which the CRL is downloaded.

If the web administrator cannot identify the type of validation process being used, this is a finding.'

# START_DESCRIBE V-13672
# No check possible
# STOP_DESCRIBE V-13672

end

