# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13737 - The HTTP request header fields must be limited. '
control 'V-13737' do
  impact 0.5
  title 'The HTTP request header fields must be limited. '
  desc 'Buffer overflow attacks are carried out by a malicious attacker sending amounts of data that the web server cannot store in a given size buffer. The eventual overflow of this buffer can overwrite system memory. Subsequently an attacker may be able to elevate privileges and take control of the server. This Apache directives limits the size of the various HTTP header sizes thereby limiting the chances for a buffer overflow.  The LimitRequestFields directive allows the server administrator to modify the limit on the number of request header fields allowed in an HTTP request. A server needs this value to be larger than the number of fields that a normal client request might include. The number of request header fields used by a client rarely exceeds 20, but this may vary among different client implementations, often depending upon the extent to which a user has configured their browser to support detailed content negotiation. Optional HTTP extensions are often expressed using request header fields.  This directive gives the server administrator greater control over abnormal client request behavior, which may be useful for avoiding some forms of denial-of-service attacks. The value should be increased if normal clients see an error response from the server that indicates too many fields were sent in the request. '
  tag 'stig', 'V-13737'
  tag severity: 'medium'
  tag checkid: 'C-33620r1_chk'
  tag fixid: 'F-29252r1_fix'
  tag version: 'WA000-WWA062 A22'
  tag ruleid: 'SV-32757r1_rule'
  tag fixtext: 'Edit the httpd.conf file and set LimitRequestFields Directive to a value greater than 0. '
  tag checktext: 'To view the LimitRequestFields value enter the following command:

grep "LimitRequestFields" /usr/local/apache2/conf/httpd.conf.

If the value of LimitRequestFields is not set to a value greater than 0, this is a finding. 
'

# START_DESCRIBE V-13737
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('LimitRequestFields') { should cmp > 0 }
  end
# STOP_DESCRIBE V-13737

end

