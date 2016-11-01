# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-2271 - Monitoring software must include CGI or equivalent programs in its scope.'
control 'V-2271' do
  impact 0.5
  title 'Monitoring software must include CGI or equivalent programs in its scope.'
  desc 'By their very nature, CGI type files permit the anonymous web user to interact with data and perhaps store data on the web server. In many cases, CGI scripts exercise system-level control over the server’s resources. These files make appealing targets for the malicious user. If these files can be modified or exploited, the web server can be compromised. These files must be monitored by a security tool that reports unauthorized changes to these files.  '
  tag 'stig', 'V-2271'
  tag severity: 'medium'
  tag checkid: 'C-33621r2_chk'
  tag fixid: 'F-29255r1_fix'
  tag version: 'WG440 A22'
  tag ruleid: 'SV-32927r2_rule'
  tag fixtext: 'Use a monitoring tool to monitor changes to the CGI or equivalent directory. This can be done with something as simple as a script or batch file that would identify a change in the file. 
'
  tag checktext: 'CGI or equivalent files must be monitored by a security tool that reports unauthorized changes. It is the purpose of such software to monitor key files for unauthorized changes to them. The reviewer should query the ISSO, the SA, and the web administrator and verify the information provided by asking to see the template file or configuration file of the software being used to accomplish this security task. Example file extensions for files considered to provide active content are, but not limited to, .cgi, .asp, .aspx, .class, .vb, .php, .pl, and .c. 

If the site does not have a process in place to monitor changes to CGI program files, this is a finding.'

# START_DESCRIBE V-2271
# No Check possible
# STOP_DESCRIBE V-2271

end

