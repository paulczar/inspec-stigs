# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-2225 - MIME types for csh or sh shell programs must be disabled.'
control 'V-2225' do
  impact 0.5
  title 'MIME types for csh or sh shell programs must be disabled.'
  desc 'Users must not be allowed to access the shell programs. Shell programs might execute shell escapes and could then perform unauthorized activities that could damage the security posture of the web server. A shell is a program that serves as the basic interface between the user and the operating system. In this regard, there are shells that are security risks in the context of a web server and shells that are unauthorized in the context of the Security Features Users Guide.'
  tag 'stig', 'V-2225'
  tag severity: 'medium'
  tag checkid: 'C-31107r2_chk'
  tag fixid: 'F-26772r1_fix'
  tag version: 'WG370 A22'
  tag ruleid: 'SV-36309r2_rule'
  tag fixtext: 'Disable MIME types for csh or sh shell programs.'
  tag checktext: 'Enter the following commands: 

grep "Action" /usr/local/apache2/conf/httpd.conf grep "AddHandler" /usr/local/apache2/conf/httpd.conf 

If either of these exist and they configure /bin/csh, or any other shell as a viewer for documents, this is a finding.'

# START_DESCRIBE V-2225
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('Action') { should_not match /\/bin/ }
    its('AddHandler') { should_not match /\/bin/ }
  end
# STOP_DESCRIBE V-2225

end

