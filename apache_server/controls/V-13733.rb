# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13733 - Server side includes (SSIs) must run with execution capability disabled.'
control 'V-13733' do
  impact 1.0
  title 'Server side includes (SSIs) must run with execution capability disabled.'
  desc 'The Options directive configures the web server features that are available in particular directories.  The IncludesNOEXEC feature controls the ability of the server to utilize SSIs while disabling the exec command, which is used to execute external scripts.  If the full includes feature is used it could allow the execution of malware leading to a system compromise. '
  tag 'stig', 'V-13733'
  tag severity: 'high'
  tag checkid: 'C-33615r1_chk'
  tag fixid: 'F-29246r1_fix'
  tag version: 'WA000-WWA054 A22'
  tag ruleid: 'SV-32753r1_rule'
  tag fixtext: 'Edit the httpd.conf file and add one of the following to the enabled Options directive:

+IncludesNoExec
-IncludesNoExec
-Includes

Remove the ‘Includes’ or ‘+Includes’ setting from the options statement. '
  tag checktext: 'To view the Options value enter the following command:

grep "Options" /usr/local/apache2/conf/httpd.conf. 

Review all uncommented Options statements for the following values:

+IncludesNoExec
-IncludesNoExec
-Includes 

If these values don’t exist this is a finding.

Notes:
- If the value does NOT exist, this is a finding.
- If all enabled Options statement are set to None this is not a finding.
'

# START_DESCRIBE V-13733
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('Options.to_s') { should match /\+IncludesNoExec/ }
    its('Options.to_s') { should match /-IncludesNoExec/ }
    its('Options.to_s') { should match /-Includes/ }
  end
# STOP_DESCRIBE V-13733

end

