# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26327 - The URL-path name must be set to the file path name or the directory path name.'
control 'V-26327' do
  impact 0.5
  title 'The URL-path name must be set to the file path name or the directory path name.'
  desc 'The ScriptAlias directive controls which directories the Apache server "sees" as containing scripts.  If the directive uses a URL-path name that is different than the actual file system path, the potential exists to expose the script source code.'
  tag 'stig', 'V-26327'
  tag severity: 'medium'
  tag checkid: 'C-33784r1_chk'
  tag fixid: 'F-29427r1_fix'
  tag version: 'WA00560 A22'
  tag ruleid: 'SV-33229r1_rule'
  tag fixtext: 'Edit the httpd.conf file and set the ScriptAlias URL-path and file-path or directory-path entries.'
  tag checktext: 'Enter the following command:

grep "ScriptAlias" /usr/local/apache2/conf/httpd.conf.  

If any enabled ScriptAlias directive do not have matching URL-path and file-path or directory-path entries, this is a finding.
'

# START_DESCRIBE V-26327
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  entries = apache_conf(conf_file).ScriptAlias
  entries.each { |entry|
    describe entry do
      it { should match /\/.+\/\s+"\/.+\/"/ }
    end
    url_path = command("echo #{entry} | awk '{print $1}'").stdout.chomp
    file_path = command("echo #{entry} | awk '{print $2}'").stdout.chomp
    describe file_path do
      it { should match url_path }
    end
  }
# STOP_DESCRIBE V-26327

end

