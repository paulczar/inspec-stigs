# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26368 - Automatic directory indexing must be disabled.'
control 'V-26368' do
  impact 0.5
  title 'Automatic directory indexing must be disabled.'
  desc 'To identify the type of web servers and versions software installed it is common for attackers to scan for icons or special content specific to the server type and version. A simple request like http://example.com/icons/apache_pb2.png may tell the attacker that the server is Apache 2.2 as shown below. The many icons are used primary for auto indexing, which is recommended to be disabled.'
  tag 'stig', 'V-26368'
  tag severity: 'medium'
  tag checkid: 'C-33828r1_chk'
  tag fixid: 'F-29492r1_fix'
  tag version: 'WA00515 A22'
  tag ruleid: 'SV-33219r1_rule'
  tag fixtext: 'Edit the httpd.conf file and remove autoindex_module.'
  tag checktext: 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules. If autoindex_module is found, this is a finding.'

# START_DESCRIBE V-26368
  describe command('httpd -t -D DUMP_MODULES') do
    its('stdout') { should_not match /autoindex_module/i }
  end
# STOP_DESCRIBE V-26368

end

