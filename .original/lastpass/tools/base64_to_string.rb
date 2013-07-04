#!/usr/bin/env ruby

# This script converts base64 encoded data from a file to a C# string.

require 'stringio'
require 'base64'

def str b64
    begin
        Base64.strict_decode64 b64
    rescue
        abort "The data doesn't seem to be base64 encoded"
    end

    lines = []
    StringIO.open b64 do |io|
        until io.eof?
            lines << io.read(64)
        end
    end

    lines.map { |i| %Q{"#{i}"} }.join " +\n"
end

puts str File.read ARGV[0]
