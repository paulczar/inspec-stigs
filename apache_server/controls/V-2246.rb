# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-2246 - Web server software must be a vendor-supported version.'
control 'V-2246' do
  impact 1.0
  title 'Web server software must be a vendor-supported version.'
  desc 'Many vulnerabilities are associated with older versions of web server software. As hot fixes and patches are issued, these solutions are included in the next version of the server software. Maintaining the web server at a current version makes the efforts of a malicious user to exploit the web service more difficult.'
  tag 'stig', 'V-2246'
  tag severity: 'high'
  tag checkid: 'C-29915r5_chk'
  tag fixid: 'F-2295r5_fix'
  tag version: 'WG190 A22'
  tag ruleid: 'SV-36441r2_rule'
  tag fixtext: 'Install the current version of the web server software and maintain appropriate service packs and patches.'
  tag checktext: 'To determine the version of the Apache software that is running on the system. Use the command:

httpd –v

httpd2 –v

If the version of Apache is not at the following version or higher, this is a finding.

Apache httpd server version 2.2 - Release 2.2.31 (July 2015)

Note: In some situations, the Apache software that is being used is supported by another vendor, such as Oracle in the case of the Oracle Application Server or IBMs HTTP Server. 
The versions of the software in these cases may not match the above mentioned version numbers. If the site can provide vendor documentation showing the version of the web server is supported, this would not be a finding.
'

# START_DESCRIBE V-2246
  describe package('httpd') do
    its('version') { should cmp >= '2.2.31' }
  end
# STOP_DESCRIBE V-2246

end

