# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13726 - The KeepAliveTimeout directive must be defined.'
control 'V-13726' do
  impact 0.5
  title 'The KeepAliveTimeout directive must be defined.'
  desc 'The number of seconds Apache will wait for a subsequent request before closing the connection. Once a request has been received, the timeout value specified by the Timeout directive applies. Setting KeepAliveTimeout to a high value may cause performance problems in heavily loaded servers. The higher the timeout, the more server processes will be kept occupied waiting on connections with idle clients. These requirements are set to mitigate the effects of several types of denial of service attacks. '
  tag 'stig', 'V-13726'
  tag severity: 'medium'
  tag checkid: 'C-33610r1_chk'
  tag fixid: 'F-29216r1_fix'
  tag version: 'WA000-WWA024 A22'
  tag ruleid: 'SV-32877r1_rule'
  tag fixtext: 'Edit the httpd.conf file and set the value of "KeepAliveTimeout" to the value of 15 or less.'
  tag checktext: 'To view the KeepAliveTimeout value enter the following command:

grep "KeepAliveTimeout" /usr/local/apache2/conf/httpd.conf.

If the value of "KeepAliveTimeout" is not set to 15 or less, this is a finding.

Note: If the directive does not exist, this is not a finding because it will default to 5. It is recommended that the directive be explicitly set to prevent unexpected results should the defaults for any reason change(i.e. software update).'

# START_DESCRIBE V-13726
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('KeepAliveTimeout') { should cmp <= 15 }
  end
# STOP_DESCRIBE V-13726

end

