# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26305 - The process ID (PID) file must be properly secured.'
control 'V-26305' do
  impact 0.5
  title 'The process ID (PID) file must be properly secured.'
  desc 'The PidFile directive sets the file path to the process ID file to which the server records the process id of the server, which is useful for sending a signal to the server process or for checking on the health of the process. If the PidFile is placed in a writable directory, other accounts could create a denial of service attack and prevent the server from starting by creating a PID file with the same name.'
  tag 'stig', 'V-26305'
  tag severity: 'medium'
  tag checkid: 'C-33765r1_chk'
  tag fixid: 'F-29402r1_fix'
  tag version: 'WA00530 A22'
  tag ruleid: 'SV-33222r1_rule'
  tag fixtext: 'Modify the location, permissions, and/or ownership for the PID file folder. '
  tag checktext: 'Enter the following command:

more /usr/local/Apache2.2/conf/httpd.conf.

Review the httpd.conf file and search for the following uncommented directive:  PidFile
Note the location and name of the PID file.
If the PidFile directive is not found enabled in the conf file, use /logs as the directory containing the Scoreboard file.
Verify the permissions and ownership on the folder containing the PID file. If any user accounts other than root, auditor, or the account used to run the web server have permission to, or ownership of, this folder, this is a finding. If the PID file is located in the web server DocumentRoot this is a finding.'

# START_DESCRIBE V-26305
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  pid_file =  command('find / -type f -name httpd.pid').stdout.chomp
  pid_dir = File.dirname("#{pid_file}")
  describe command("grep ^PidFile #{conf_file}") do
    its('stdout') { should match /.+/ }
  end
    describe file(pid_dir) do
    its('group') { should match /(root|auditor|apache)/ }
  end
# STOP_DESCRIBE V-26305

end
