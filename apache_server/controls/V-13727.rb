# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13727 - The httpd.conf StartServers directive must be set properly.'
control 'V-13727' do
  impact 0.5
  title 'The httpd.conf StartServers directive must be set properly.'
  desc 'These requirements are set to mitigate the effects of several types of denial of service attacks. Although there is some latitude concerning the settings themselves, the requirements attempt to provide reasonable limits for the protection of the web server. If necessary, these limits can be adjusted to accommodate the operational requirement of a given system.  From Apache.org: The StartServers directive sets the number of child server processes created on startup. As the number of processes is dynamically controlled depending on the load, there is usually little reason to adjust this parameter.  The default value differs from MPM to MPM. For worker the default is StartServers 3. For prefork defaults to 5 and for mpmt_os2 to 2.'
  tag 'stig', 'V-13727'
  tag severity: 'medium'
  tag checkid: 'C-10979r2_chk'
  tag fixid: 'F-13175r1_fix'
  tag version: 'WA000-WWA026 A22'
  tag ruleid: 'SV-36645r2_rule'
  tag fixtext: 'Open the httpd.conf file with an editor and search for the following directive:

StartServer

Set the directive to a value between 5 and 10, add the directive if it does not exist.

It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.
'
  tag checktext: 'Locate the Apache httpd.conf file.  If you cannot locate the file, you can do a search of the drive to find the location of the file.  

Open the httpd.conf file with an editor and search for the following directive:

StartServers

The value needs to be between 5 and 10 

If the directive is set improperly, this is a finding.

If the directive does not exist, this is NOT a finding because it will default to 5.  It is recommended that the directive be explicitly set to prevent unexpected results if the defaults change with updated software.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the site has operational reasons for the use of increased or decreased value. If the site has this documentation, this should be marked as Not a Finding.
'

# START_DESCRIBE V-13727
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  entries = apache_conf(conf_file).StartServers
  entries.each { |entry|
    describe entry do
      it { should cmp < 10 }
      it { should cmp > 5 }
    end
  }
# STOP_DESCRIBE V-13727

end

