# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-2230 - Backup interactive scripts on the production web server are prohibited.'
control 'V-2230' do
  impact 0.1
  title 'Backup interactive scripts on the production web server are prohibited.'
  desc 'Copies of backup files will not execute on the server, but they can be read by the anonymous user if special precautions are not taken. Such backup copies contain the same sensitive information as the actual script being executed and, as such, are useful to malicious users. Techniques and systems exist today that search web servers for such files and are able to exploit the information contained in them.   Backup copies of files are automatically created by some text editors such as emacs and edit plus. The emacs editor will write a backup file with an extension ~ added to the name of the original file. The edit plus editor will create a .bak file. Of course, this would imply the presence and use of development tools on the web server, which is a finding under WG130. Having backup scripts on the web server provides one more opportunity for malicious persons to view these scripts and use the information found in them. '
  tag 'stig', 'V-2230'
  tag severity: 'low'
  tag checkid: 'C-30362r1_chk'
  tag fixid: 'F-27282r1_fix'
  tag version: 'WG420 A22'
  tag ruleid: 'SV-6930r1_rule'
  tag fixtext: 'Ensure that CGI backup scripts are not left on the production web server.'
  tag checktext: 'This check is limited to CGI/interactive content and not static HTML.

Search for backup copies of CGI scripts on the web server or ask the SA or the Web Administrator if they keep backup copies of CGI scripts on the web server. 

Common backup file extensions are: *.bak, *.old, *.temp, *.tmp, *.backup, *.??0. This would also apply to .jsp files. 

UNIX: 
find / name “*.bak” –print
find / name “*.*~” –print
find / name “*.old” –print 

If files with these extensions are found in either the document directory or the home directory of the web server, this is a finding. 

If files with these extensions are stored in a repository (not in the document root) as backups for the web server, this is a finding.

If files with these extensions have no relationship with web activity, such as a backup batch file for operating system utility, and they are not accessible by the web application, this is not a finding. 
'

# START_DESCRIBE V-2230
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  doc_root =  command("grep ^DocumentRoot #{conf_file} | awk -F '\"' '{print $2}'").stdout.chomp
  describe command("find #{doc_root} -name '*.bak'") do
    its('stdout') { should_not match /.+/ }
  end

  describe command("find #{doc_root} -name '*.*~'") do
    its('stdout') { should_not match /.+/ }
  end

  describe command("find #{doc_root} -name '*.old'") do
    its('stdout') { should_not match /.+/ }
  end
# STOP_DESCRIBE V-2230

end

