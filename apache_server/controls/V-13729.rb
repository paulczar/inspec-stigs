# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13729 - The httpd.conf MaxSpareServers directive must be set properly. '
control 'V-13729' do
  impact 0.1
  title 'The httpd.conf MaxSpareServers directive must be set properly. '
  desc 'These requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.  From Apache.org:The MaxSpareServers directive sets the desired maximum number of idle child server processes. An idle process is one which is not handling a request. If there are more than MaxSpareServers idle, then the parent process will kill off the excess processes.  Tuning of this parameter should only be necessary on very busy sites. Setting this parameter to a large number is almost always a bad idea. If you are trying to set the value equal to or lower than MinSpareServers, Apache will automatically adjust it to MinSpareServers + 1.'
  tag 'stig', 'V-13729'
  tag severity: 'low'
  tag checkid: 'C-10981r2_chk'
  tag fixid: 'F-13177r1_fix'
  tag version: 'WA000-WWA030 A22'
  tag ruleid: 'SV-36648r2_rule'
  tag fixtext: 'Open the httpd.conf file with an editor and search for the following directive:

MaxSpareServers

Set the directive to a value of 10 or less, add the directive if it does not exist.

It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.
'
  tag checktext: 'Open the httpd.conf file with an editor and search for the following directive:

MaxSpareServers

The value needs to be 10 or less

If the directive is set improperly, this is a finding.

If the directive is not found, you will need to review the httpd.conf file to see if there are other .conf files that are included of "linked" to the httpd.conf. The other conf files may contain these directives.


If the directive does not exist, this is NOT a finding because it will default to 10.  It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of increased value. If the site has this documentation, this should be marked as Not a Finding.
'

# START_DESCRIBE V-13729
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('MaxSpareServers') { should cmp <= 10 }
  end
# STOP_DESCRIBE V-13729

end

