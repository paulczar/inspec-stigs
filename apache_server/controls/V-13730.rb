# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13730 - The httpd.conf MaxClients directive must be set properly.'
control 'V-13730' do
  impact 0.5
  title 'The httpd.conf MaxClients directive must be set properly.'
  desc 'These requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.  From Apache.org: The MaxClients directive sets the limit on the number of simultaneous requests that will be served. Any connection attempts over the MaxClients limit will normally be queued, up to a number based on the ListenBacklog directive. Once a child process is freed at the end of a different request, the connection will then be serviced.  For non-threaded servers (i.e., prefork), MaxClients translates into the maximum number of child processes that will be launched to serve requests. The default value is 256; to increase it, you must also raise ServerLimit.  For threaded and hybrid servers (e.g. beos or worker) MaxClients restricts the total number of threads that will be available to serve clients. The default value for beos is 50. For hybrid MPMs the default value is 16 (ServerLimit) multiplied by the value of 25 (ThreadsPerChild). Therefore, to increase MaxClients to a value that requires more than 16 processes, you must also raise ServerLimit.'
  tag 'stig', 'V-13730'
  tag severity: 'medium'
  tag checkid: 'C-10982r2_chk'
  tag fixid: 'F-13178r3_fix'
  tag version: 'WA000-WWA032 A22'
  tag ruleid: 'SV-36649r2_rule'
  tag fixtext: 'Open the httpd.conf file with an editor and search for the following directive:

MaxClients

Set the directive to a value of 256 or less, add the directive if it does not exist.

It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.
'
  tag checktext: 'Open the httpd.conf file with an editor and search for the following directive:

MaxClients

The value needs to be 256 or less

If the directive is set improperly, this is a finding.

If the directive does not exist, this is NOT a finding because it will default to 256.  It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of increased value. If the site has this documentation, this should be marked as Not a Finding.
'

# START_DESCRIBE V-13730
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('MaxClients') { should cmp <= 256 }
  end
# STOP_DESCRIBE V-13730

end

