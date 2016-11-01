# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-2243 - A private web server must be located on a separate controlled access subnet.'
control 'V-2243' do
  impact 0.5
  title 'A private web server must be located on a separate controlled access subnet.'
  desc 'Private web servers, which host sites that serve controlled access data, must be protected from outside threats in addition to insider threats. Insider threat may be accidental or intentional but, in either case, can cause a disruption in service of the web server. To protect the private web server from these threats, it must be located on a separate controlled access subnet and must not be a part of the public DMZ that houses the public web servers. It also cannot be located inside the enclave as part of the local general population LAN.'
  tag 'stig', 'V-2243'
  tag severity: 'medium'
  tag checkid: 'C-33627r1_chk'
  tag fixid: 'F-29263r1_fix'
  tag version: 'WA070 A22'
  tag ruleid: 'SV-32935r1_rule'
  tag fixtext: 'Isolate the private web server from the public DMZ and separate it from the internal general population LAN. '
  tag checktext: 'Verify the site’s network diagram and visually check the web server, to ensure that the private web server is located on a separate controlled access subnet and is not a part of the public DMZ that houses the public web servers. In addition, the private web server needs to be isolated via a controlled access mechanism from the local general population LAN.'

# START_DESCRIBE V-2243
# No Check possible
# STOP_DESCRIBE V-2243

end

