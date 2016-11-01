# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26324 - Web server options for the OS root must be disabled.'
control 'V-26324' do
  impact 0.5
  title 'Web server options for the OS root must be disabled.'
  desc 'The Apache Options directive allows for specific configuration of options, including execution of CGI, following symbolic links, server side includes, and content negotiation. The Options directive for the root OS level is used to create a default minimal options policy that allows only the minimal options at the root directory level. Then for specific web sites or portions of the web site, options may be enabled as needed and appropriate. No options should be enabled and the value for the Options Directive should be None.'
  tag 'stig', 'V-26324'
  tag severity: 'medium'
  tag checkid: 'C-33780r1_chk'
  tag fixid: 'F-29422r1_fix'
  tag version: 'WA00545 A22'
  tag ruleid: 'SV-33213r1_rule'
  tag fixtext: 'Ensure the root directory has the appropriate Options assignment.'
  tag checktext: 'Enter the following command:

more /usr/local/Apache2.2/conf/httpd.conf.

Review the httpd.conf file and search for the following  directive:

Directory 

For every root directory entry (i.e. <Directory />) ensure the following entry exists:

Options None

If the statement above is not found in the root directory statement, this is a finding.  

If Allow directives are included in the root directory statement, this is a finding.  

If the root directory statement is not found at all, this is a finding.'

# START_DESCRIBE V-26324
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe command("awk '/<Directory \\/>/,/<\\/Directory>/' #{conf_file}") do
    its('stdout') { should match /Options\s+None$/ }
  end
# STOP_DESCRIBE V-26324

end

