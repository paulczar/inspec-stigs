# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-2259 - Web server system files must conform to minimum file permission requirements.'
control 'V-2259' do
  impact 0.5
  title 'Web server system files must conform to minimum file permission requirements.'
  desc 'This check verifies that the key web server system configuration files are owned by the SA or the web administrator controlled account. These same files that control the configuration of the web server, and thus its behavior, must also be accessible by the account that runs the web service. If these files are altered by a malicious user, the web server would no longer be under the control of its managers and owners; properties in the web server configuration could be altered to compromise the entire server platform.'
  tag 'stig', 'V-2259'
  tag severity: 'medium'
  tag checkid: 'C-33630r1_chk'
  tag fixid: 'F-29268r1_fix'
  tag version: 'WG300 A22'
  tag ruleid: 'SV-32938r1_rule'
  tag fixtext: 'Use the chmod command to set permissions on the web server system directories and files as follows.

root dir
apache	      root	WebAdmin	771/660
/apache/cgi-bin    root	WebAdmin	775/775
/apache/bin	       root	WebAdmin	550/550
/apache/config     root	WebAdmin	770/660
/apache/htdocs    root	WebAdmin	775/664
/apache/logs       root	WebAdmin	750/640


'
  tag checktext: 'Apache directory and file permissions and ownership should be set per the following table.. The installation directories may vary from one installation to the next.  If used, the WebAmins group should contain only accounts of persons authorized to manage the web server configuration, otherwise the root group should own all Apache files and directories. 

If the files and directories are not set to the following permissions or more restrictive, this is a finding.

To locate the ServerRoot directory enter the following command.
grep ^ ServerRoot /usr/local/apache2/conf/httpd.conf

/Server
root dir
apache	      root	WebAdmin	771/660

/apache/cgi-bin    root	WebAdmin	775/775
/apache/bin	       root	WebAdmin	550/550
/apache/config     root	WebAdmin	770/660
/apache/htdocs    root	WebAdmin	775/664
/apache/logs       root	WebAdmin	750/640

NOTE:  The permissions are noted as directories / files'

# START_DESCRIBE V-2259
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  server_root =  command("grep ^DocumentRoot #{conf_file} | awk -F '\"' '{print $2}'").stdout.chomp
  describe file(server_root) do
    its('owner') { should eq 'root' }
    its('group') { should eq 'root' }
  end
# STOP_DESCRIBE V-2259

end

