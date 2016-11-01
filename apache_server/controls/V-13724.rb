# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13724 - The Timeout directive must be properly set.'
control 'V-13724' do
  impact 0.5
  title 'The Timeout directive must be properly set.'
  desc 'The Timeout requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.'
  tag 'stig', 'V-13724'
  tag severity: 'medium'
  tag checkid: 'C-10976r1_chk'
  tag fixid: 'F-13172r1_fix'
  tag version: 'WA000-WWA020 A22'
  tag ruleid: 'SV-32977r1_rule'
  tag fixtext: 'Edit the httpd.conf file and set the value of "Timeout" to 300 seconds or less.'
  tag checktext: 'To view the Timeout value enter the following command:

grep "Timeout" /usr/local/apache2/conf/httpd.conf.

Verify the value is 300 or less if not, this is a finding.

Note:If the directive does not exist, this is not a finding because it will default to 300.  It is recommended that the directive be explicitly set to prevent unexpected results should the defaults for any reason be changed (i.e. software update).
'

# START_DESCRIBE V-13724
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('Timeout') { should cmp <= 300 }
  end
# STOP_DESCRIBE V-13724

end

