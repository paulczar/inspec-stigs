# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26326 - The web server must be configured to listen on a specific IP address and port.'
control 'V-26326' do
  impact 0.5
  title 'The web server must be configured to listen on a specific IP address and port.'
  desc 'The Apache Listen directive specifies the IP addresses and port numbers the Apache web server will listen for requests. Rather than be unrestricted to listen on all IP addresses available to the system, the specific IP address or addresses intended must be explicitly specified. Specifically a Listen directive with no IP address specified, or with an IP address of zero’s should not be used. Having multiple interfaces on web servers is fairly common, and without explicit Listen directives, the web server is likely to be listening on an inappropriate IP address / interface that were not intended for the web server. Single homed system with a single IP addressed are also required to have an explicit IP address in the Listen directive, in case additional interfaces are added to the system at a later date.'
  tag 'stig', 'V-26326'
  tag severity: 'medium'
  tag checkid: 'C-33782r1_chk'
  tag fixid: 'F-29425r1_fix'
  tag version: 'WA00555 A22'
  tag ruleid: 'SV-33228r1_rule'
  tag fixtext: 'Edit the httpd.conf file and set the "Listen directive" to listen on a specific IP address and port. '
  tag checktext: 'Enter the following command:

grep "Listen" /usr/local/apache2/conf/httpd.conf

Review the results for the following  directive:   Listen 

For any enabled Listen directives ensure they specify both an IP address and port number.

If the Listen directive is found with only an IP address, or only a port number specified, this is finding.  
If the IP address is all zeros (i.e. 0.0.0.0:80 or [::ffff:0.0.0.0]:80, this is a finding.  
If the Listen directive does not exist, this is a finding.'

# START_DESCRIBE V-26326
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  entries = apache_conf(conf_file).Listen
  entries.each { |entry|
    describe entry do
      it { should match /.+/ }
      it { should match /\d{1,}.\d{1,}.\d{1,}.\d{1,}:\d{1,}$/ }
      it { should_not match /[0].[0].[0].[0]/ }
    end
  }
# STOP_DESCRIBE V-26326

end

