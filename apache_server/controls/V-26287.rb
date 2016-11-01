# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26287 - Web Distributed Authoring and Versioning (WebDAV) must be disabled.'
control 'V-26287' do
  impact 0.5
  title 'Web Distributed Authoring and Versioning (WebDAV) must be disabled.'
  desc 'The Apache mod_dav and mod_dav_fs modules support WebDAV (Web-based Distributed Authoring and Versioning) functionality for Apache. WebDAV is an extension to the HTTP protocol which allows clients to create, move, and delete files and resources on the web server. WebDAV is not widely used, and has serious security concerns as it may allow clients to modify unauthorized files on the web server. Therefore, the WebDav modules mod_dav and mod_dav_fs should be disabled.'
  tag 'stig', 'V-26287'
  tag severity: 'medium'
  tag checkid: 'C-33754r1_chk'
  tag fixid: 'F-29390r1_fix'
  tag version: 'WA00505 A22'
  tag ruleid: 'SV-33216r1_rule'
  tag fixtext: 'Edit the httpd.conf file and remove the following modules:

dav_module
dav_fs_module
dav_lock_module'
  tag checktext: 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules.  If any of the following modules are found, this is a finding. 

dav_module
dav_fs_module
dav_lock_module'

# START_DESCRIBE V-26287
  describe command('httpd -t -D DUMP_MODULES') do
    its('stdout') { should_not match /dav_module/i }
    its('stdout') { should_not match /dav_fs_module/i }
    its('stdout') { should_not match /dav_lock_module/i }
  end
# STOP_DESCRIBE V-26287

end

