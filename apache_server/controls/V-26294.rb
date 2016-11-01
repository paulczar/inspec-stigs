# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26294 - Web server status module must be disabled.'
control 'V-26294' do
  impact 0.5
  title 'Web server status module must be disabled.'
  desc 'The Apache mod_info module provides information on the server configuration via access to a /server-info URL location, while the mod_status module provides current server performance statistics. While having server configuration and status information available as a web page may be convenient, it is recommended that these modules not be enabled: Once mod_info is loaded into the server, its handler capability is available in per-directory .htaccess files and can leak sensitive information from the configuration directives of other Apache modules such as system paths, usernames/passwords, database names, etc. If mod_status is loaded into the server, its handler capability is available in all configuration files, including per-directory files (e.g., .htaccess) and may have security-related ramifications.'
  tag 'stig', 'V-26294'
  tag severity: 'medium'
  tag checkid: 'C-33759r1_chk'
  tag fixid: 'F-29395r1_fix'
  tag version: 'WA00510 A22'
  tag ruleid: 'SV-33218r1_rule'
  tag fixtext: 'Edit the httpd.conf file and disable info_module and status_module.'
  tag checktext: 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules.  If any of the following modules are found, this is a finding.

info_module
status_module'

# START_DESCRIBE V-26294
  describe command('httpd -t -D DUMP_MODULES') do
    its('stdout') { should_not match /info_module/i }
    its('stdout') { should_not match /status_module/i }
  end
# STOP_DESCRIBE V-26294

end

