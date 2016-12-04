#!/usr/bin/env ruby
require 'nokogiri'
require 'optparse'

# Gather inputs from CLI for input and destination files
OptionParser.new do |o|
  o.on('-i FILENAME') { |i| $input = i }
  o.on('-d FILENAME') { |d| $dest = d }
  o.on('-h') { puts o; exit }
  o.parse!
end

# Set input to a parsable attribute
doc = File.open($input) { |f| Nokogiri::XML(f) }

# Get date from XML
dates = doc.css('//status')
date = dates[0]['date']

# Get description from XML
stigdesc = doc.css('//description')[0]

# Get all groups from XML
groups = doc.css('//Group')

# Parse groups
xml  = Nokogiri::XML(groups.to_s)

# Parse and write each field to a file.
groups.each do |group|
  xml_doc  = Nokogiri::XML(group)
  xml  = Nokogiri::XML(group.to_s)
  id = xml.css('@id')[0]
  title1 = xml.css('title').first
  title2 = xml.css('title').last
  sevprep = xml.css('Rule')
  impact = sevprep[0]['severity']
  case impact
  when 'low'
    sev = '0.1'
  when 'medium'
    sev = '0.5'
  when 'high'
    sev = '1.0'
  else
    puts 'There was an issue getting the severity'
  end
  ctrldesc = xml.css('description')[1]
  cd = Nokogiri::XML(ctrldesc)
  cdesc = cd.css('VulnDiscussion')
  checkident = xml.css('check')
  checkid = checkident[0]['system']
  fixident = xml.css('fixtext')
  fixid = fixident[0]['fixref']
  vers = xml.css('version')
  ruleid = sevprep[0]['id']
  checktxt = xml.css('check-content')
  output = <<-HEREDOC
# encoding: utf-8
# copyright: 2016, you
# license: All rights reserved
# date: #{date}
# description: #{stigdesc.text.gsub("\n", " ")}
# impacts
title '#{id} - #{title2.text}'
control '#{id}' do
  impact #{sev}
  title '#{title2.text}'
  desc '#{cdesc.text.gsub("\n", " ").gsub("'", "\\\\'")}'
  tag 'stig', '#{id}'
  tag severity: '#{impact}'
  tag checkid: '#{checkid}'
  tag fixid: '#{fixid}'
  tag version: '#{vers.text}'
  tag ruleid: '#{ruleid}'
  tag fixtext: '#{fixident.text.gsub("'", "\\\\'")}'
  tag checktext: '#{checktxt.text.gsub("'", "\\\\'")}'

# START_DESCRIBE #{id}
  describe file('') do
    it { should match // }
  end
# STOP_DESCRIBE #{id}

end

  HEREDOC
  File.write("#{$dest}/#{id}.rb", output)
end
