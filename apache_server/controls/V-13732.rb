# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13732 - The "–FollowSymLinks” setting must be disabled.

'
control 'V-13732' do
  impact 0.5
  title 'The "–FollowSymLinks” setting must be disabled.

'
  desc 'The Options directive configures the web server features that are available in particular directories. The FollowSymLinks option controls the ability of the server to follow symbolic links. A symbolic link allows a file or a directory to be referenced using a symbolic name raising a potential hazard if symbolic linkage is made to a sensitive area. When web scripts are executed and symbolic links are allowed, the web user could be allowed to access locations on the web server that are outside the scope of the web document root or home directory.'
  tag 'stig', 'V-13732'
  tag severity: 'medium'
  tag checkid: 'C-39081r1_chk'
  tag fixid: 'F-34186r1_fix'
  tag version: 'WA000-WWA052 A22'
  tag ruleid: 'SV-40129r1_rule'
  tag fixtext: 'Edit the httpd.conf file and set the value of "FollowSymLinks" to "-FollowSymLinks".'
  tag checktext: 'To view the Options value enter the following command:

grep "Options" /usr/local/apache2/conf/httpd.conf.

Review all uncommented Options statements for the following value: -FollowSymLinks 

If the value is found with an Options statement, and it does not have a preceding ‘-‘, this is a finding.

Notes:
- If the value does NOT exist, this is a finding.
- If all enabled Options statement are set to None this is not a finding.'

# START_DESCRIBE V-13732
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('Options.to_s') { should match /-FollowSymLinks/ }
  end
# STOP_DESCRIBE V-13732

end

