# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-13621 - All web server documentation, sample code, example applications, and tutorials must be removed from a production web server.'
control 'V-13621' do
  impact 1.0
  title 'All web server documentation, sample code, example applications, and tutorials must be removed from a production web server.'
  desc 'Web server documentation, sample code, example applications, and tutorials may be an exploitable threat to a web server. A production web server may only contain components that are operationally necessary (e.g., compiled code, scripts, web-content, etc.). Delete all directories that contain samples and any scripts used to execute the samples. If there is a requirement to maintain these directories at the site on non-production servers for training purposes, have NTFS permissions set to only allow access to authorized users (i.e., web administrators and systems administrators). Sample applications or scripts have not been evaluated and approved for use and may introduce vulnerabilities to the system.'
  tag 'stig', 'V-13621'
  tag severity: 'high'
  tag checkid: 'C-33626r1_chk'
  tag fixid: 'F-29260r1_fix'
  tag version: 'WG385 A22'
  tag ruleid: 'SV-32933r1_rule'
  tag fixtext: 'Ensure sample code and documentation have been removed from the web server.'
  tag checktext: 'Query the SA to determine if all directories that contain samples and any scripts used to execute the samples have been removed from the server. Each web server has its own list of sample files. This may change with the software versions, but the following are some examples of what to look for (This should not be the definitive list of sample files, but only an example of the common samples that are provided with the associated web server. This list will be updated as additional information is discovered.):

ls -Ll /usr/local/apache2/manual.

If there is a requirement to maintain these directories at the site for training or other such purposes, have permissions or set the permissions to only allow access to authorized users. If any sample files are found on the web server, this is a finding.'

# START_DESCRIBE V-13621
  only_if do
    file('/usr/local/apache2/manual').exist?
  end

  describe file('/usr/local/apache2/manual') do
    its('mode') { should_not match /0$/ }
  end
# STOP_DESCRIBE V-13621

end

