# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13738 - The HTTP request header field size must be limited.'
control 'V-13738' do
  impact 0.5
  title 'The HTTP request header field size must be limited.'
  desc 'Buffer overflow attacks are carried out by a malicious attacker sending amounts of data that the web server cannot store in a given size buffer. The eventual overflow of this buffer can overwrite system memory. Subsequently an attacker may be able to elevate privileges and take control of the server. This Apache directives limits the size of the various HTTP header sizes thereby limiting the chances for a buffer overflow.   The LimitRequestFieldSize directive allows the server administrator to reduce or increase the limit on the allowed size of an HTTP request header field. A server needs this value to be large enough to hold any one header field from a normal client request. The size of a normal request header field will vary greatly among different client implementations, often depending upon the extent to which a user has configured their browser to support detailed content negotiation. SPNEGO authentication headers can be up to 12392 bytes.  This directive gives the server administrator greater control over abnormal client request behavior, which may be useful for avoiding some forms of denial-of-service attacks. '
  tag 'stig', 'V-13738'
  tag severity: 'medium'
  tag checkid: 'C-33622r4_chk'
  tag fixid: 'F-29256r4_fix'
  tag version: 'WA000-WWA064 A22'
  tag ruleid: 'SV-32766r2_rule'
  tag fixtext: 'Edit the httpd.conf file and ensure the LimitRequestFieldSize is explicitly configured and set to 8190 or other approved value. '
  tag checktext: 'To view the LimitRequestFieldSize value enter the following command:

grep "LimitRequestFieldSize" /usr/local/apache2/conf/httpd.conf.

If no LimitRequestFieldSize directives exist, this is a Finding. Although the default value is 8190, this directive must be explicitly set.

If the value of LimitRequestFieldSize is not set to 8190, this is a finding.
'

# START_DESCRIBE V-13738
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('LimitRequestFieldSize') { should cmp 8190 }
  end
# STOP_DESCRIBE V-13738

end

