# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13739 - The HTTP request line must be limited.'
control 'V-13739' do
  impact 0.5
  title 'The HTTP request line must be limited.'
  desc 'Buffer overflow attacks are carried out by a malicious attacker sending amounts of data that the web server cannot store in a given size buffer. The eventual overflow of this buffer can overwrite system memory. Subsequently an attacker may be able to elevate privileges and take control of the server. This Apache directives limits the size of the various HTTP header sizes thereby limiting the chances for a buffer overflow.   The LimitRequestLine directive allows the server administrator to reduce or increase the limit on the allowed size of a clients HTTP request-line. Since the request-line consists of the HTTP method, URI, and protocol version, the LimitRequestLine directive places a restriction on the length of a request-URI allowed for a request on the server. A server needs this value to be large enough to hold any of its resource names, including any information that might be passed in the query part of a GET request.  This directive gives the server administrator greater control over abnormal client request behavior, which may be useful for avoiding some forms of denial-of-service attacks. '
  tag 'stig', 'V-13739'
  tag severity: 'medium'
  tag checkid: 'C-33624r2_chk'
  tag fixid: 'F-29258r2_fix'
  tag version: 'WA000-WWA066 A22'
  tag ruleid: 'SV-32768r2_rule'
  tag fixtext: 'Edit the httpd.conf file and set the LimitRequestLine to 8190 or other approved value. If no LimitRequestLine directives exist, explicitly add the directive and set to 8190.'
  tag checktext: 'To view the LimitRequestLine value enter the following command:

grep "LimitRequestLine" /usr/local/apache2/conf/httpd.conf.

If the value of LimitRequestLine is not set to 8190, this is a finding.
If no LimitRequestLine directives exist, this is a Finding. Although the default value is 8190, this directive must be explicitly set.'

# START_DESCRIBE V-13739
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('LimitRequestLine') { should cmp 8190 }
  end
# STOP_DESCRIBE V-13739

end

