# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13735 - Directory indexing must be disabled on directories not containing index files.'
control 'V-13735' do
  impact 0.5
  title 'Directory indexing must be disabled on directories not containing index files.'
  desc 'Directory options directives are directives that can be applied to further restrict access to file and directories.  If a URL which maps to a directory is requested, and there is no DirectoryIndex (e.g., index.html) in that directory, then mod_autoindex will return a formatted listing of the directory which is not acceptable.'
  tag 'stig', 'V-13735'
  tag severity: 'medium'
  tag checkid: 'C-33617r1_chk'
  tag fixid: 'F-29248r1_fix'
  tag version: 'WA000-WWA058 A22'
  tag ruleid: 'SV-32755r1_rule'
  tag fixtext: 'Edit the httpd.conf file and add an "-" to the Indexes setting, or set the options directive to None. '
  tag checktext: 'To view the Indexes value enter the following command: 

grep "Indexes" /usr/local/apache2/conf/httpd.conf. 

Review all uncommented Options statements for the following value: -Indexes 

If the value is found on the Options statement, and it does not have a preceding ‘-‘, this is a finding. 

Notes:
- If the value does NOT exist, this is a finding.
- If all enabled Options statement are set to None this is not a finding.
'

# START_DESCRIBE V-13735
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('Options.to_s') { should match /-Indexes/ }
  end
# STOP_DESCRIBE V-13735

end

