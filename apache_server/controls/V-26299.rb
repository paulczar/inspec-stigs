# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26299 - The web server must not be configured as a proxy server.'
control 'V-26299' do
  impact 0.5
  title 'The web server must not be configured as a proxy server.'
  desc 'The Apache proxy modules allow the server to act as a proxy (either forward or reverse proxy) of http and other protocols with additional proxy modules loaded. If the Apache installation is not intended to proxy requests to or from another network then the proxy module should not be loaded. Proxy servers can act as an important security control when properly configured, however a secure proxy server is not within the scope of this STIG. A web server should be primarily a web server or a proxy server but not both, for the same reasons that other multi-use servers are not recommended. Scanning for web servers that will also proxy requests is a very common attack, as proxy servers are useful for anonymizing attacks on other servers, or possibly proxying requests into an otherwise protected network.'
  tag 'stig', 'V-26299'
  tag severity: 'medium'
  tag checkid: 'C-33762r1_chk'
  tag fixid: 'F-29398r1_fix'
  tag version: 'WA00520 A22'
  tag ruleid: 'SV-33220r1_rule'
  tag fixtext: 'Edit the httpd.conf file and remove the following modules:

proxy_module
proxy_ajp_module
proxy_balancer_module
proxy_ftp_module
proxy_http_module
proxy_connect_module'
  tag checktext: 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules. If any of the following modules are found this is a finding:

proxy_module
proxy_ajp_module
proxy_balancer_module
proxy_ftp_module
proxy_http_module
proxy_connect_module'

# START_DESCRIBE V-26299
  describe command('httpd -t -D DUMP_MODULES') do
    its('stdout') { should_not match /proxy_module/i }
    its('stdout') { should_not match /proxy_ajp_module/i }
    its('stdout') { should_not match /proxy_balancer_module/i }
    its('stdout') { should_not match /proxy_ftp_module/i }
    its('stdout') { should_not match /proxy_http_module/i }
    its('stdout') { should_not match /proxy_connect_module/i }
  end
# STOP_DESCRIBE V-26299

end

