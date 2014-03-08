#!/usr/bin/env ruby

# Reencrypts a piece of data from one encryption key to another.
# File requires some editing before running. There are too many
# parameters involved to make this generic. It's a throw away
# tool anyway.

require "openssl"

def decode64 s
	s.unpack("m").first
end

def decode_hex s
	s.scan(/../).map { |i| i.to_i 16 }.pack "c*"
end

def encode_hex s
	s.bytes.map { |i| "%02x" % i }.join
end

def decrypt_aes256 cipher, iv, data, encryption_key
	aes = OpenSSL::Cipher::Cipher.new "aes-256-#{cipher}"
    aes.decrypt
    aes.key = encryption_key
    aes.iv = iv
    aes.update(data) + aes.final
end

def encrypt_aes256 cipher, iv, data, encryption_key
	aes = OpenSSL::Cipher::Cipher.new "aes-256-#{cipher}"
    aes.encrypt
    aes.key = encryption_key
    aes.iv = iv
    aes.update(data) + aes.final
end

def reencrypt_prik prik_hex, from_key_base64, to_key_base64
	prik = decode_hex prik_hex
	from_key = decode64 from_key_base64
	to_key = decode64 to_key_base64

	decrypted = decrypt_aes256 "cbc", from_key[0, 16], prik, from_key
	encode_hex encrypt_aes256 "cbc", to_key[0, 16], decrypted, to_key
end

from_key_base64 = ""
to_key_base64 = ""
prik_hex = ""

puts reencrypt_prik prik_hex, from_key_base64, to_key_base64
