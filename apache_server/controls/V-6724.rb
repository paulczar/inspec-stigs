# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-6724 - Web server and/or operating system information must be protected.

'
control 'V-6724' do
  impact 0.1
  title 'Web server and/or operating system information must be protected.

'
  desc 'The web server response header of an HTTP response can contain several fields of information including the requested HTML page. The information included in this response can be web server type and version, operating system and version, and ports associated with the web server. This provides the malicious user valuable information without the use of extensive tools.'
  tag 'stig', 'V-6724'
  tag severity: 'low'
  tag checkid: 'C-29517r1_chk'
  tag fixid: 'F-26581r1_fix'
  tag version: 'WG520 A22'
  tag ruleid: 'SV-36672r1_rule'
  tag fixtext: 'Edit the /usr/local/apache2/conf/httpd.conf file and ensure the directive is set to Prod.

'
  tag checktext: 'Enter the following command:

grep "ServerTokens" /usr/local/apache2/conf/httpd.conf

The directive ServerTokens must be set to “Prod” (ex. ServerTokens Prod).  This directive controls whether Server response header field that is sent back to clients that includes a description of the OS-type of the server as well as information about compiled-in modules.

If the web server or operating system information are sent to the client via the server response header or the directive does not exist, this is a finding.  

Note: The default value is set to Full.'

# START_DESCRIBE V-6724
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE V-6724

end

