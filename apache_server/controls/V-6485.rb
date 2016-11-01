# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-6485 - Web server content and configuration files must be part of a routine backup program.'
control 'V-6485' do
  impact 0.1
  title 'Web server content and configuration files must be part of a routine backup program.'
  desc 'Backing up web server data and web server application software after upgrades or maintenance ensures that recovery can be accomplished up to the current version. It also provides a means to determine and recover from subsequent unauthorized changes to the software and data.  A tested and verifiable backup strategy will be implemented for web server software as well as all web server data files. Backup and recovery procedures will be documented and the Web Manager or SA for the specific application will be responsible for the design, test, and implementation of the procedures.        The site will have a contingency processing plan/disaster recovery plan that includes web servers. The contingency plan will be periodically tested in accordance with DoDI 8500.2 requirements.  The site will identify an off-site storage facility in accordance with DoDI 8500.2 requirements. Off-site backups will be updated on a regular basis and the frequency will be documented in the contingency plan. '
  tag 'stig', 'V-6485'
  tag severity: 'low'
  tag checkid: 'C-33651r2_chk'
  tag fixid: 'F-29284r1_fix'
  tag version: 'WA140 A22'
  tag ruleid: 'SV-32964r2_rule'
  tag fixtext: 'Document the backup procedures. 
'
  tag checktext: 'Interview the Information Systems Security Officer (ISSO), SA, Web Manager, Webmaster or developers as necessary to determine whether or not a tested and verifiable backup strategy has been implemented for web server software as well as all web server data files.

Proposed Questions:
Who maintains the backup and recovery procedures?
Do you have a copy of the backup and recovery procedures?
Where is the off-site backup location?
Is the contingency plan documented?
When was the last time the contingency plan was tested?
Are the test dates and results documented?

If there is not a backup and recovery process for the web server, this is a finding.
'

# START_DESCRIBE V-6485
# No Check possible
# STOP_DESCRIBE V-6485

end

