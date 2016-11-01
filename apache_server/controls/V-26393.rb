# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26393 - The ability to override the access configuration for the OS root directory must be disabled.'
control 'V-26393' do
  impact 0.5
  title 'The ability to override the access configuration for the OS root directory must be disabled.'
  desc 'The Apache OverRide directive allows for .htaccess files to be used to override much of the configuration, including authentication, handling of document types, auto generated indexes, access control, and options. When the server finds an .htaccess file (as specified by AccessFileName) it needs to know which directives declared in that file can override earlier access information. When this directive is set to None, then .htaccess files are completely ignored. In this case, the server will not even attempt to read .htaccess files in the file system. When this directive is set to All, then any directive which has the .htaccess Context is allowed in .htaccess files.'
  tag 'stig', 'V-26393'
  tag severity: 'medium'
  tag checkid: 'C-33831r1_chk'
  tag fixid: 'F-29497r1_fix'
  tag version: 'WA00547 A22'
  tag ruleid: 'SV-33232r1_rule'
  tag fixtext: 'Edit the httpd.conf file and add or set the value of AllowOverride to "None".
'
  tag checktext: 'Enter the following command:

more /usr/local/Apache2.2/conf/httpd.conf.

Review the httpd.conf file and search for the following directive:

Directory 

For every root directory entry (i.e. <Directory />) ensure the following entry exists:

AllowOverride None

If the statement above is not found in the root directory statement, this is a finding. 

If Allow directives are included in the root directory statement, this is a finding.

If the root directory statement is not listed at all, this is a finding.
'

# START_DESCRIBE V-26393
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe command("awk '/<Directory \\/>/,/<\\/Directory>/' #{conf_file}") do
    its('stdout') { should match /AllowOverride\s+None$/ }
  end
# STOP_DESCRIBE V-26393

end

