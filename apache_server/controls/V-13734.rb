# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13734 - The MultiViews directive must be disabled.'
control 'V-13734' do
  impact 0.5
  title 'The MultiViews directive must be disabled.'
  desc 'Directory options directives are directives that can be applied to further restrict access to file and directories. MultiViews is a per-directory option, meaning it can be set with an Options directive within a ,  or  section in httpd.conf, or (if AllowOverride is properly set) in .htaccess files. The effect of MultiViews is as follows: if the server receives a request for /some/dir/foo, if /some/dir has MultiViews enabled, and /some/dir/foo does not exist, then the server reads the directory looking for files named foo.*, and effectively fakes up a type map which names all those files, assigning them the same media types and content-encodings it would have if the client had asked for one of them by name. It then chooses the best match to the clients requirements.falseWeb AdministratorECSC-1'
  tag 'stig', 'V-13734'
  tag severity: 'medium'
  tag checkid: 'C-33616r1_chk'
  tag fixid: 'F-29247r1_fix'
  tag version: 'WA000-WWA056 A22'
  tag ruleid: 'SV-32754r1_rule'
  tag fixtext: 'Edit the httpd.conf file and add the "-" to the MultiViews setting, or set the options directive to None. 
'
  tag checktext: 'To view the MultiViews value enter the following command:

grep "MultiView" /usr/local/apache2/conf/httpd.conf.

Review all uncommented Options statements for the following value: -MultiViews 

If the value is found on the Options statement, and it does not have a preceding ‘-‘, this is a finding. 

Notes:
- If the value does NOT exist, this is a finding.
- If all enabled Options statement are set to None this is not a finding.
'

# START_DESCRIBE V-13734
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('Options.to_s') { should match /-MultiViews/ }
  end
# STOP_DESCRIBE V-13734

end

