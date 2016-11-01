# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13725 - The KeepAlive directive must be enabled.'
control 'V-13725' do
  impact 0.5
  title 'The KeepAlive directive must be enabled.'
  desc 'The KeepAlive extension to HTTP/1.0 and the persistent connection feature of HTTP/1.1 provide long lived HTTP sessions which allow multiple requests to be sent over the same connection. These requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.'
  tag 'stig', 'V-13725'
  tag severity: 'medium'
  tag checkid: 'C-10977r2_chk'
  tag fixid: 'F-13173r1_fix'
  tag version: 'WA000-WWA022 A22'
  tag ruleid: 'SV-32844r2_rule'
  tag fixtext: 'Edit the httpd.conf file and set the value of "KeepAlive" to "On"'
  tag checktext: 'To view the KeepAlive value enter the following command:

grep "KeepAlive" /usr/local/apache2/conf/httpd.conf.

Verify the Value of KeepAlive is set to “On” If not, this is a finding. 

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for not using persistent connections. If the site has this documentation, this should be marked as Not a Finding.
'

# START_DESCRIBE V-13725
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('KeepAlive') { should eq ['On'] }
  end
# STOP_DESCRIBE V-13725

end

