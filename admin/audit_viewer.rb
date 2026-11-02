#!/usr/bin/env ruby


require 'json'
require 'time'

path = ARGV[0] || File.join(Dir.home, '.sc-archive', 'audit.jsonl')
begin
  metadata = File.lstat(path)
  abort 'Audit log must be a regular file, not a symbolic link.' if metadata.symlink? || !metadata.file?
rescue Errno::ENOENT
  abort "Audit log not found: #{path}"
end
abort 'Audit log is unexpectedly large.' if metadata.size > 64 * 1024 * 1024

safe = lambda do |value, maximum = 24|
  value.to_s.gsub(/[[:cntrl:]]/, '?').byteslice(0, maximum).to_s
end

display_path = safe.call(File.expand_path(path), 180)
puts "SC Archive audit log: #{display_path}"
puts format('%-22s %-10s %-12s %-8s', 'TIME (UTC)', 'ACTION', 'RESULT', 'VERSION')
puts '-' * 58

File.foreach(path).with_index(1) do |line, number|
  if line.bytesize > 8192
    warn "Skipping oversized audit entry at line #{number}."
    next
  end
  begin
    item = JSON.parse(line)
    time = Time.at(Integer(item.fetch('at_unix'))).utc.iso8601
    action = safe.call(item.fetch('action'), 10)
    result = safe.call(item.fetch('result'), 12)
    version = safe.call(item.fetch('version'), 8)
    puts format('%-22s %-10s %-12s %-8s', time, action, result, version)
  rescue StandardError
    warn "Skipping invalid log entry at line #{number}."
  end
end
