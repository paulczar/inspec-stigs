# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13728 - The httpd.conf MinSpareServers directive must be set properly. '
control 'V-13728' do
  impact 0.5
  title 'The httpd.conf MinSpareServers directive must be set properly. '
  desc 'These requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.  From Apache.org: The MinSpareServers directive sets the desired minimum number of idle child server processes. An idle process is one which is not handling a request. If there are fewer than MinSpareServers idle, then the parent process creates new children at a maximum rate of 1 per second.  Tuning of this parameter should only be necessary on very busy sites. Setting this parameter to a large number is almost always a bad idea.'
  tag 'stig', 'V-13728'
  tag severity: 'medium'
  tag checkid: 'C-10980r2_chk'
  tag fixid: 'F-13176r1_fix'
  tag version: 'WA000-WWA028 A22'
  tag ruleid: 'SV-36646r2_rule'
  tag fixtext: 'Open the httpd.conf file with an editor and search for the following directive:

MinSpareServers

Set the directive to a value of between 5 and 10, add the directive if it does not exist.

It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.
'
  tag checktext: 'Open the httpd.conf file with an editor and search for the following directive:

MinSpareServers

The value needs to be between 5 and 10

If the directive is set improperly, this is a finding.

If the directive is not found, you will need to review the httpd.conf file to see if there are other .conf files that are included of "linked" to the httpd.conf. The other conf files may contain these directives.

If the directive does not exist, this is NOT a finding because it will default to 5.  It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of increased  or decreased value. If the site has this documentation, this should be marked as Not a Finding.
'

# START_DESCRIBE V-13728
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('MinSpareServers') { should cmp > 5 }
    its('MinSpareServers') { should cmp < 10 }
  end
# STOP_DESCRIBE V-13728

end

