#!/usr/bin/env ruby

# Splits a string to be pasted into source code.

lines = []
File.open ARGV[0] do |io|
	until io.eof?
		lines << %Q{"#{io.read 64}"}
	end
end

puts lines.join " +\n"
