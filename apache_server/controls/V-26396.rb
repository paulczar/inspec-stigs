# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26396 - HTTP request methods must be limited.'
control 'V-26396' do
  impact 0.5
  title 'HTTP request methods must be limited.'
  desc 'The HTTP 1.1 protocol supports several request methods which are rarely used and potentially high risk. For example, methods such as PUT and DELETE are rarely used and should be disabled in keeping with the primary security principal of minimize features and options. Also since the usage of these methods is typically to modify resources on the web server, they should be explicitly disallowed. For normal web server operation, you will typically need to allow only the GET, HEAD and POST request methods. This will allow for downloading of web pages and submitting information to web forms. The OPTIONS request method will also be allowed as it is used to request which HTTP request methods are allowed.'
  tag 'stig', 'V-26396'
  tag severity: 'medium'
  tag checkid: 'C-33833r1_chk'
  tag fixid: 'F-29499r1_fix'
  tag version: 'WA00565 A22'
  tag ruleid: 'SV-33236r1_rule'
  tag fixtext: 'Edit the https.conf file and add the following entries for every enabled directory except root.

Order allow,deny

<LimitExcept GET POST OPTIONS>
     Deny from all
</LimitExcept>
'
  tag checktext: 'Enter the following command:

more /usr/local/apache2/conf/httpd.conf

For every enabled <Directory> directive (except root), ensure the following entry exists:

Order allow,deny

<LimitExcept GET POST OPTIONS>
Deny from all
</LimitExcept>

If the statement above is found in the root directory statement (i.e. <Directory />), this is a finding. 

If the statement above is found enabled but without the appropriate LimitExcept or Order statement, this is a finding. 

If the statement is not found inside an enabled <Directory> directive, this is a finding.

Note: If the LimitExcept statement above is operationally limiting. This should be explicitly documented with the Web Manager, at which point this can be considered not a finding.'

# START_DESCRIBE V-26396
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe command("awk '/<Directory \\/>/,/<\\/Directory>/' #{conf_file}") do
    its('stdout') { should_not match /Order\s+allow,deny$/ }
    its('stdout') { should_not match /<LimitExcept GET POST OPTIONS>\nDeny\s+from\s+all\n<\/LimitExcept>/ }
  end
  d = command("grep -i '^<Directory' #{conf_file} |grep -v 'Directory /'").stdout
  directories = []
  directories = d.split(/\n/)
  directories.each { |dir|
    val_dir = dir.gsub(/\//, "\\/")
    describe command("awk '/#{val_dir}/,/<\\/Directory>/' #{conf_file}") do
      its('stdout') { should match /Order\s+allow,deny$/ }
      its('stdout') { should match /<LimitExcept GET POST OPTIONS>\nDeny\s+from\s+all\n<\/LimitExcept>/ }
    end
  }
# STOP_DESCRIBE V-26396

end
