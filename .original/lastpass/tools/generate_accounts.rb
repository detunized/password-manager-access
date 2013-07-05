#!/usr/bin/env ruby

# This script generates test data in CSV format to be imported into the LastPass account.
# Requires the faker gem. To install run "gem install faker".

require "faker"
include Faker

def rand range
    Random.new.rand range
end

def name kind = [:company, :domain].sample
    case kind
    when :company
        Company.name
    when :domain
        Internet.domain_name
    else
        fail "Unknown name kind"
    end
end

def username kind = [:name, :email].sample
    case kind
    when :name
        Internet.user_name
    when :email
        Internet.email
    else
        fail "Unknown username kind"
    end
end

def password kind = [:bad, :soso, :secure].sample
    case kind
    when :bad
        Lorem.word
    when :soso
        ('a'..'z').to_a.sample(rand 4..8).join + ('0'..'9').to_a.sample(rand 2..4).join
    when :secure
        (('A'..'Z').to_a + ('a'..'z').to_a + ('0'..'9').to_a + '!@#$%^&*?'.scan(/./)).sample(rand 12..24).join
    else
        fail "Unknown password kind"
    end
end

def url
	Internet.url
end

def group
	["", "one", "two", "three", "four"].sample
end

puts "name,username,password,url,grouping"
100.times { puts %Q{"#{name}","#{username}","#{password}","#{url}","#{group}"} }
