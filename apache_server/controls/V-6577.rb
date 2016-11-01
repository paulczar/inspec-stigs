# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-6577 - A web server must be segregated from other services.'
control 'V-6577' do
  impact 0.5
  title 'A web server must be segregated from other services.'
  desc 'The web server installation and configuration plan should not support the co-hosting of multiple services such as Domain Name Service (DNS), e-mail, databases, search engines, indexing, or streaming media on the same server that is providing the web publishing service.  By separating these services additional defensive layers are established between the web service and the applicable application should either be compromised.     Disallowed or restricted services in the context of this vulnerability applies to services that are not directly associated with the delivery of web content. An operating system that supports a web server will not provide other services (e.g., domain controller, e-mail server, database server, etc.). Only those services necessary to support the web server and its hosted sites are specifically allowed and may include, but are not limited to, operating system, logging, anti-virus, host intrusion detection, administrative maintenance, or network requirements. '
  tag 'stig', 'V-6577'
  tag severity: 'medium'
  tag checkid: 'C-33633r1_chk'
  tag fixid: 'F-29274r1_fix'
  tag version: 'WG204 A22'
  tag ruleid: 'SV-32950r1_rule'
  tag fixtext: 'Move or install additional services and applications to partitions that are not the operating system root or the web document root.
'
  tag checktext: 'Request a copy of and review the web server’s installation and configuration plan. Ensure that the server is in compliance with this plan. If the server is not in compliance with the plan, this is a finding.

Query the SA to ascertain if and where the additional services are installed.

Confirm that the additional service or application is not installed on the same partition as the operating systems root directory or the web document root. If it is, this is a finding.
'

# START_DESCRIBE V-6577
# No Check possible
# STOP_DESCRIBE V-6577

end

