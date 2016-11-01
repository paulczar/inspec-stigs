# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13731 - All interactive programs must be placed in a designated directory with appropriate permissions.'
control 'V-13731' do
  impact 0.5
  title 'All interactive programs must be placed in a designated directory with appropriate permissions.'
  desc 'Directory options directives are directives that can be applied to further restrict access to file and directories.  The Options directive controls which server features are available in a particular directory. The ExecCGI option controls the execution of CGI scripts using mod_cgi.  This needs to be restricted to only the directory intended for script execution.'
  tag 'stig', 'V-13731'
  tag severity: 'medium'
  tag checkid: 'C-33613r1_chk'
  tag fixid: 'F-29240r1_fix'
  tag version: 'WA000-WWA050 A22'
  tag ruleid: 'SV-32763r1_rule'
  tag fixtext: 'Locate any cgi-bin files and directories enabled in the Apache configuration via Script, ScriptAlias or other Script* directives.

Remove the printenv default CGI in cgi-bin directory if it is installed. 

rm $APACHE_PREFIX/cgi-bin/printenv. 

Remove the test-cgi file from the cgi-bin directory if it is installed. 

rm $APACHE_PREFIX/cgi-bin/test-cgi. 

Review and remove any other cgi-bin files which are not needed for business purposes.'
  tag checktext: 'Search for the unnecessary CGI programs which may be found in the directories configured with ScriptAlias, Script or other Script* directives. Often, CGI directories are named cgi-bin. Also, CGI AddHandler or SetHandler directives may also be in use for specific handlers such as perl, python and PHP.

To search the http.conf file for Options enter the following command:

grep "Options" /usr/local/apache2/conf/httpd.conf.

If the value for Options is returned with a ExecCGI (no +) this is a finding.'

# START_DESCRIBE V-13731
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('Options') { should_not match /ExecCGI/i }
  end
# STOP_DESCRIBE V-13731

end

