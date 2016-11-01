# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-2256 - The access control files are owned by a privileged web server account.'
control 'V-2256' do
  impact 0.5
  title 'The access control files are owned by a privileged web server account.'
  desc 'This check verifies that the key web server system configuration files are owned by the SA or Web Manager controlled account. These same files which control the configuration of the web server, and thus its behavior, must also be accessible by the account which runs the web service. If these files are altered by a malicious user, the web server would no longer be under the control of its managers and owners; properties in the web server configuration could be altered to compromise the entire server platform. '
  tag 'stig', 'V-2256'
  tag severity: 'medium'
  tag checkid: 'C-2677r1_chk'
  tag fixid: 'F-6761r1_fix'
  tag version: 'WG280'
  tag ruleid: 'SV-6880r1_rule'
  tag fixtext: 'The site needs to ensure that the owner should be the non-privileged web server account or equivalent which runs the web service; however, the group permissions represent those of the user accessing the web site that must execute the directives in .htacces.'
  tag checktext: 'This check verifies that the SA or Web Manager controlled account owns the key web server files. These same files, which control the configuration of the web server, and thus its behavior, must also be accessible by the account that runs the web service process. 

If it exists, the following file need to be owned by a privileged account.

.htaccess
httpd.conf

Use the command find / -name httpd.conf to find the file
Change to the Directory that contains the httpd.conf file
Use the command ls -l httpd.conf to determine ownership of the file

-The Web Manager or the SA should own all the system files and directories. 
-The configurable directories can be owned by the WebManager or equivalent user.  

Permissions on these files should be 660 or more restrictive.

If root or an authorized user does not own the web system files and the permission are not correct, this is a finding.'

# START_DESCRIBE V-2256
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe file(conf_file) do
    its('mode') { should cmp <= 600 }
  end
# STOP_DESCRIBE V-2256

end

