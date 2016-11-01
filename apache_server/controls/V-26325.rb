# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26325 - The TRACE  method must be disabled.'
control 'V-26325' do
  impact 0.5
  title 'The TRACE  method must be disabled.'
  desc 'Diagnostics help establish a history of activities, and can be useful in detecting attack attempts or determining tuning adjustments to improve server availability. Trace logs are essential to the investigation and prosecution of unauthorized access to web server software and data. However, in standard production operations, use of diagnostics may reveal undiscovered vulnerabilities and ultimately, to compromise of the data. Because of the potential for abuse, the HTTP Trace method should be disabled.'
  tag 'stig', 'V-26325'
  tag severity: 'medium'
  tag checkid: 'C-33781r1_chk'
  tag fixid: 'F-29424r1_fix'
  tag version: 'WA00550 A22'
  tag ruleid: 'SV-33227r1_rule'
  tag fixtext: 'Edit the httpd.conf file and add or set the value of EnableTrace to "Off".'
  tag checktext: 'Enter the following command:

grep "TraceEnable" /usr/local/apache2/conf/httpd.conf.

Review the results for the following directive:

TraceEnable.

For any enabled TraceEnable directives ensure they are part of the server level configuration (i.e. not nested in a <Directory> or <Location> directive). Also ensure that the TraceEnable directive is set to “Off”.

If the TraceEnable directive is not part of the server level configuration and/or is not set to “Off”, this is a finding.

If the directive does not exist in the conf file, this is a finding because the default value is "On".
'

# START_DESCRIBE V-26325
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  describe apache_conf(conf_file) do
    its('TraceEnable') { should eq 'Off' }
  end
# STOP_DESCRIBE V-26325

end

