# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13620 - A private web server’s list of CAs in a trust hierarchy must lead to an authorized  DoD PKI Root CA.'
control 'V-13620' do
  impact 0.5
  title 'A private web server’s list of CAs in a trust hierarchy must lead to an authorized  DoD PKI Root CA.'
  desc 'A PKI certificate is a digital identifier that establishes the identity of an individual or a platform. A server that has a certificate provides users with third-party confirmation of authenticity. Most web browsers perform server authentication automatically and the user is notified only if the authentication fails. The authentication process between the server and the client is performed using the SSL/TLS protocol. Digital certificates are authenticated, issued, and managed by a trusted Certificate Authority (CA).  The use of a trusted certificate validation hierarchy is crucial to the ability to control access to a site’s server and to prevent unauthorized access. Only DoD-approved PKIs will be utilized. '
  tag 'stig', 'V-13620'
  tag severity: 'medium'
  tag checkid: 'C-33628r1_chk'
  tag fixid: 'F-29265r1_fix'
  tag version: 'WG355 A22'
  tag ruleid: 'SV-32936r1_rule'
  tag fixtext: 'Configure the web server’s trust store to trust only DoD-approved PKIs (e.g., DoD PKI, DoD ECA, and DoD-approved external partners).'
  tag checktext: 'Enter the following command: 

find / -name ssl.conf  note the path of the file. 

grep "SSLCACertificateFile" /path/of/ssl.conf  

Review the results to determine the path of the SSLCACertificateFile. 

more /path/of/ca-bundle.crt 

Examine the contents of this file to determine if the trusted CAs are DoD approved. If the trusted CA that is used to authenticate users to the web site does not lead to an approved DoD CA, this is a finding. 

NOTE: There are non DoD roots that must be on the server in order for it to function. Some applications, such as anti-virus programs, require root CAs to function. DoD approved certificate can include the External Certificate Authorities (ECA), if approved by the DAA. The PKE InstallRoot 3.06 System Administrator Guide (SAG), dated 8 Jul 2008, contains a complete list of DoD, ECA, and IECA CAs.'

# START_DESCRIBE V-13620
# May have to be configured on a case by case basis.
# STOP_DESCRIBE V-13620

end

