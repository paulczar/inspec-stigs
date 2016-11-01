# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13736 - The HTTP request message body size must be limited.'
control 'V-13736' do
  impact 0.5
  title 'The HTTP request message body size must be limited.'
  desc 'Buffer overflow attacks are carried out by a malicious attacker sending amounts of data that the web server cannot store in a given size buffer. The eventual overflow of this buffer can overwrite system memory. Subsequently an attacker may be able to elevate privileges and take control of the server. The Apache directives listed below limit the size of the various HTTP header sizes thereby limiting the chances for a buffer overflow.   The LimitRequestBody directive allows the user to set a limit on the allowed size of an HTTP request message body within the context in which the directive is given (server, per-directory, per-file or per-location). If the client request exceeds that limit, the server will return an error response instead of servicing the request. The size of a normal request message body will vary greatly depending on the nature of the resource and the methods allowed on that resource. CGI scripts typically use the message body for retrieving form information. Implementations of the PUT method will require a value at least as large as any representation that the server wishes to accept for that resource. '
  tag 'stig', 'V-13736'
  tag severity: 'medium'
  tag checkid: 'C-33618r1_chk'
  tag fixid: 'F-29249r1_fix'
  tag version: 'WA000-WWA060 A22'
  tag ruleid: 'SV-32756r1_rule'
  tag fixtext: 'Edit the httpd.conf file and specify a size for the LimitRequestBody directive. '
  tag checktext: 'To view the LimitRequestBody value enter the following command: 

grep "LimitRequestBody" /usr/local/apache2/conf/httpd.conf.

If the value of LimitRequestBody is not set to 1 or greater or does not exist, this is a finding. 

Note: The default value is set to unlimited. It is recommended that the directive be explicitly set to prevent unexpected results should the defaults change with updated software.'

# START_DESCRIBE V-13736
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('LimitRequestBody') { should cmp >= 1 }
  end
# STOP_DESCRIBE V-13736

end

