# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-60707 - The web server must remove all export ciphers from the cipher suite.'
control 'V-60707' do
  impact 0.5
  title 'The web server must remove all export ciphers from the cipher suite.'
  desc 'During the initial setup of a Transport Layer Security (TLS) connection to the web server, the client sends a list of supported cipher suites in order of preference.  The web server will reply with the cipher suite it will use for communication from the client list.  If an attacker can intercept the submission of cipher suites to the web server and place, as the preferred cipher suite, a weak export suite, the encryption used for the session becomes easy for the attacker to break, often within minutes to hours.'
  tag 'stig', 'V-60707'
  tag severity: 'medium'
  tag checkid: 'C-61651r2_chk'
  tag fixid: 'F-66387r2_fix'
  tag version: 'WG345 A22'
  tag ruleid: 'SV-75159r1_rule'
  tag fixtext: 'Update the cipher specification string for all enabled SSLCipherSuite directives to include !EXPORT.'
  tag checktext: 'Locate the Apache httpd.conf and ssl.conf file if available.
Open the httpd.conf and ssl.conf file with an editor and search for the following uncommented directive: SSLCipherSuite
For all enabled SSLCipherSuite directives, ensure the cipher specification string contains the kill cipher from list option for all export cipher suites, i.e., !EXPORT, which may be abbreviated !EXP.  If the SSLCipherSuite directive does not contain !EXPORT or there are no enabled SSLCipherSuite directives, this is a finding.
'

# START_DESCRIBE V-60707
  conf_file = command('find / -type f -name httpd.conf').stdout.chomp
  ssl_file = command('find / -type f -name ssl.conf').stdout.chomp
  if file(conf_file).exist?
    describe apache_conf(conf_file) do
      its('SSLCipherSuite') { should match /(!EXPORT|!EXP)/ }
    end
  end
  if file(ssl_file).exist?
    describe apache_conf(conf_file) do
      its('SSLCipherSuite') { should match /(!EXPORT|!EXP)/ }
    end
  end
# STOP_DESCRIBE V-60707

end
