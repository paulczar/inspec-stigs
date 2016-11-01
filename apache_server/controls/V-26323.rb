# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26323 - The web server must be configured to explicitly deny access to the OS root.'
control 'V-26323' do
  impact 0.5
  title 'The web server must be configured to explicitly deny access to the OS root.'
  desc 'The Apache Directory directive allows for directory specific configuration of access controls and many other features and options. One important usage is to create a default deny policy that does not allow access to Operating System directories and files, except for those specifically allowed. This is done, with denying access to the OS root directory. One aspect of Apache, which is occasionally misunderstood, is the feature of default access. That is, unless you take steps to change it, if the server can find its way to a file through normal URL mapping rules, it can and will serve it to clients. Having a default deny is a predominate security principal, and then helps prevent the unintended access, and we do that in this case by denying access to the OS root directory. The Order directive is important as it provides for other Allow directives to override the default deny.'
  tag 'stig', 'V-26323'
  tag severity: 'medium'
  tag checkid: 'C-33779r1_chk'
  tag fixid: 'F-29418r1_fix'
  tag version: 'WA00540 A22'
  tag ruleid: 'SV-33226r1_rule'
  tag fixtext: 'Edit the httpd.conf file and set the root directory directive as follows:

Directory
Order deny,allow
Deny from all'
  tag checktext: 'Enter the following command:

more /usr/local/Apache2.2/conf/httpd.conf.

Review the httpd.conf file and search for the following  directive:

Directory

For every root directory entry (i.e. <Directory />) ensure the following exists; if not, this is a finding.

Order deny,allow
Deny from all

If the statement above is not found in the root directory statement, this is a finding.

If Allow directives are included in the root directory statement, this is a finding.  '

# START_DESCRIBE V-26323
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe command("awk '/<Directory \\/>/,/<\\/Directory>/' #{conf_file}") do
    its('stdout') { should match /Order\s+deny,allow$/ }
    its('stdout') { should match /Deny\s+from\s+all$/ }
  end
# STOP_DESCRIBE V-26323

end

