# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26285 - Active software modules must be minimized.'
control 'V-26285' do
  impact 0.5
  title 'Active software modules must be minimized.'
  desc 'Modules are the source of Apache httpd servers core and dynamic capabilities. Thus not every module available is needed for operation. Most installations only need a small subset of the modules available. By minimizing the enabled modules to only those that are required, we reduce the number of doors and have therefore reduced the attack surface of the web site. Likewise having fewer modules means less software that could have vulnerabilities.'
  tag 'stig', 'V-26285'
  tag severity: 'medium'
  tag checkid: 'C-33753r1_chk'
  tag fixid: 'F-29389r1_fix'
  tag version: 'WA00500 A22'
  tag ruleid: 'SV-33215r1_rule'
  tag fixtext: 'Disable any modules that are not needed.'
  tag checktext: 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M

This will provide a list of the loaded modules. Validate that all displayed modules are required for operations. If any module is not required for operation, this is a finding.

Note:  The following modules are needed for basic web function and do not need to be reviewed:  

core_module
http_module
so_module
mpm_prefork_module'

# START_DESCRIBE V-26285
# No Check possible, this is will be unique for each use case.
# STOP_DESCRIBE V-26285

end

