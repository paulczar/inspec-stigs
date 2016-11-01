# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: 2015-08-28
# description: All directives specified in this STIG must be specifically set (i.e. the server is not allowed to revert to programmed defaults for these directives).  Included files should be reviewed if they are used.  Procedures for reviewing included files are included in the overview document.  The use of .htaccess files are not authorized for use according to the STIG.  However, if they are used, there are procedures for reviewing them in the overview document.  The Web Policy STIG should be used in addition to the Apache Site and Server STIGs in order to do a comprehensive web server review.   
# impacts
title 'V-26322 - The score board file must be properly secured.
'
control 'V-26322' do
  impact 0.5
  title 'The score board file must be properly secured.
'
  desc 'The ScoreBoardfile directive sets a file path which the server will use for Inter-Process Communication (IPC) among the Apache processes.  If the directive is specified, then Apache will use the configured file for the inter-process communication. Therefore if it is specified it needs to be located in a secure directory. If the ScoreBoardfile is placed in a writable directory, other accounts could create a denial of service attack and prevent the server from starting by creating a file with the same name, and or users could monitor and disrupt the communication between the processes by reading and writing to the file.'
  tag 'stig', 'V-26322'
  tag severity: 'medium'
  tag checkid: 'C-33778r1_chk'
  tag fixid: 'F-29415r1_fix'
  tag version: 'WA00535 A22'
  tag ruleid: 'SV-33223r1_rule'
  tag fixtext: 'The scoreboard file is created when the server starts, and is deleted when it shuts down, set the permissions during the creation of the file.'
  tag checktext: 'To determine the location of the file enter the following command:

find / -name ScoreBoard.

To view the permissions on the file enter the following command:

ls -lL /path/of/ScoreBoard.

If the permissions on the file are not set to 644 or less restrictive, this is a finding. '

# START_DESCRIBE V-26322
  score_board = command('find / -type -name ScoreBoard')
  only_if do
    file(score_board).exist?
  end
  describe file(score_board) do
    its('mode') { should cmp <= 644 }
  end
# STOP_DESCRIBE V-26322

end

