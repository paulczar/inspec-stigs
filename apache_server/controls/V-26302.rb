# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26302 - User specific directories must not be globally enabled.'
control 'V-26302' do
  impact 0.5
  title 'User specific directories must not be globally enabled.'
  desc 'The UserDir directive must be disabled so that user home directories are not accessed via the web site with a tilde (~) preceding the username. The directive also sets the path name of the directory that will be accessed. The user directories should not be globally enabled since it allows anonymous access to anything users may want to share with other users on the network. Also consider that every time a new account is created on the system, there is potentially new content available via the web site.'
  tag 'stig', 'V-26302'
  tag severity: 'medium'
  tag checkid: 'C-33764r1_chk'
  tag fixid: 'F-29401r1_fix'
  tag version: 'WA00525 A22'
  tag ruleid: 'SV-33221r1_rule'
  tag fixtext: 'Edit the httpd.conf file and remove userdir_module.'
  tag checktext: 'Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules. If userdir_module is listed, this is a finding.'

# START_DESCRIBE V-26302
  describe command('httpd -t -D DUMP_MODULES') do
    its('stdout') { should_not match /userdir_module/i }
  end
# STOP_DESCRIBE V-26302

end

