// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Numerics;
using System.Text;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class ExtensionsTest
    {
        //
        // byte
        //

        [Theory]
        [InlineData(0b0000_0000, 0b0000_0000)]
        [InlineData(0b0000_0001, 0b1000_0000)]
        [InlineData(0b0101_0101, 0b1010_1010)]
        [InlineData(0b1111_0000, 0b0000_1111)]
        [InlineData(0b1111_1111, 0b1111_1111)]
        public void Byte_ReverseBits_reverses_bits(byte original, byte reversed)
        {
            Assert.Equal(reversed, original.ReverseBits());
            Assert.Equal(original, reversed.ReverseBits());
            Assert.Equal(original, original.ReverseBits().ReverseBits());
            Assert.Equal(reversed, reversed.ReverseBits().ReverseBits());
        }

        //
        // uint
        //

        [Theory]
        [InlineData(0x0000_0000, 0x0000_0000)]
        [InlineData(0x0000_0001, 0x8000_0000)]
        [InlineData(0x0101_0101, 0x8080_8080)]
        [InlineData(0x0000_1234, 0x2C48_0000)]
        [InlineData(0xDEAD_BEEF, 0xF77D_B57B)]
        [InlineData(0xFFFF_FFFF, 0xFFFF_FFFF)]
        public void Uint_ReverseBits_reverses_bits(uint original, uint reversed)
        {
            Assert.Equal(reversed, original.ReverseBits());
            Assert.Equal(original, reversed.ReverseBits());
            Assert.Equal(original, original.ReverseBits().ReverseBits());
            Assert.Equal(reversed, reversed.ReverseBits().ReverseBits());
        }

        //
        // string
        //

        [Fact]
        public void String_IsNullOrEmpty_returns_true()
        {
            Assert.True(((string)null).IsNullOrEmpty());
            Assert.True("".IsNullOrEmpty());
        }

        [Fact]
        public void String_ToBytes_converts_string_to_utf8_bytes()
        {
            Assert.Equal(new byte[] { }, "".ToBytes());
            Assert.Equal(TestBytes, TestString.ToBytes());
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("Pj4+Pg==", ">>>>")]
        public void String_ToBase64_returns_base64(string base64, string raw)
        {
            Assert.Equal(base64, raw.ToBase64());
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("Pj4-Pg==", ">>>>")]
        public void String_ToUrlSafeBase64_returns_urlsafe_base64_with_padding(string expected, string raw)
        {
            Assert.Equal(expected, raw.ToUrlSafeBase64());
        }

        [Theory]
        [InlineData("", "")]
        [InlineData("Pj4-Pg", ">>>>")]
        public void String_ToUrlSafeBase64NoPadding_returns_urlsafe_base64_without_padding(string expected, string raw)
        {
            Assert.Equal(expected, raw.ToUrlSafeBase64NoPadding());
        }

        [Theory]
        [InlineData("", "")]
        [InlineData(";,/?:@&=+$#", ";,/?:@&=+$#")]
        [InlineData("-_.!~*'()", "-_.!~*'()")]
        [InlineData("ABC abc 123", "ABC%20abc%20123")]
        [InlineData(" #%^{}|\\\"<>`", "%20#%25%5E%7B%7D%7C%5C%22%3C%3E%60")]
        [InlineData("éåäöü", "%C3%A9%C3%A5%C3%A4%C3%B6%C3%BC")]
        public void String_EscapeUri_escapes_special_characters(string raw, string uri)
        {
            Assert.Equal(uri, raw.EncodeUri());
        }

        [Fact]
        public void String_EncodeUriData_escapes_special_characters()
        {
            Assert.Equal("blah%40gmail.com", "blah@gmail.com".EncodeUriData());
        }

        [Theory]
        [InlineData("", true)]
        [InlineData("deadbeef", true)]
        [InlineData("0", false)] // odd length
        [InlineData("badc0ffee", false)] // odd length
        [InlineData("not hex!", false)] // invalid characters
        public void String_IsHex_returns_correct_result(string hex, bool expected)
        {
            Assert.Equal(expected, hex.IsHex());
        }

        [Theory]
        [InlineData("", new byte[] { })]
        [InlineData("00", new byte[] { 0 })]
        [InlineData("00ff", new byte[] { 0, 255 })]
        [InlineData("00010203040506070809", new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 })]
        [InlineData("000102030405060708090a0b0c0d0e0f", new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 })]
        [InlineData(
            "8af633933e96a3c3550c2734bd814195",
            new byte[] { 0x8A, 0xF6, 0x33, 0x93, 0x3E, 0x96, 0xA3, 0xC3, 0x55, 0x0C, 0x27, 0x34, 0xBD, 0x81, 0x41, 0x95 }
        )]
        public void String_DecodeHex(string hex, byte[] expected)
        {
            Assert.Equal(expected, hex.ToLower().DecodeHex());
            Assert.Equal(expected, hex.ToUpper().DecodeHex());
        }

        [Fact]
        public void String_DecodeHex_throws_on_odd_length()
        {
            Exceptions.AssertThrowsInternalError(() => "0".DecodeHex(), "input length must be multiple of 2");
        }

        [Fact]
        public void String_DecodeHex_throws_on_non_hex_characters()
        {
            Exceptions.AssertThrowsInternalError(() => "xz".DecodeHex(), "invalid characters in hex");
        }

        [Theory]
        [InlineData("0", new byte[] { 0 })]
        [InlineData("f", new byte[] { 0x0F })]
        [InlineData("bad", new byte[] { 0x0B, 0xAD })]
        [InlineData("badbeef", new byte[] { 0x0B, 0xAD, 0xBE, 0xEF })]
        public void String_DecodeHexLoose_decodes_strings_with_odd_length(string hex, byte[] expected)
        {
            Assert.Equal(expected, hex.DecodeHexLoose());
        }

        // Test vectors from https://tools.ietf.org/html/rfc4648#section-10
        [Theory]
        [InlineData(new byte[] { }, "")]
        [InlineData(new byte[] { 0x66 }, "MY======")]
        [InlineData(new byte[] { 0x66, 0x6f }, "MZXQ====")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f }, "MZXW6===")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f, 0x62 }, "MZXW6YQ=")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61 }, "MZXW6YTB")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }, "MZXW6YTBOI======")]
        public void String_Decode32_decodes_base32(byte[] expected, string base32)
        {
            Assert.Equal(expected, base32.Decode32());
        }

        // Test vectors from https://tools.ietf.org/html/rfc4648#section-10
        [Theory]
        [InlineData(new byte[] { 0x66 }, "MY")]
        [InlineData(new byte[] { 0x66, 0x6f }, "MZXQ")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f }, "MZXW6")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f, 0x62 }, "MZXW6YQ")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61 }, "MZXW6YTB")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }, "MZXW6YTBOI")]
        public void String_Decode32_decodes_base32_without_padding(byte[] expected, string base32)
        {
            Assert.Equal(expected, base32.Decode32());
        }

        // Test vectors from https://tools.ietf.org/html/rfc4648#section-10
        [Theory]
        [InlineData(new byte[] { 0x66 }, "my")]
        [InlineData(new byte[] { 0x66, 0x6f }, "mzxq")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f }, "mzxw6")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f, 0x62 }, "mzxw6yq")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61 }, "mzxw6ytb")]
        [InlineData(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }, "mzxw6ytboi")]
        public void String_Decode32_decodes_base32_lowercase(byte[] expected, string base32)
        {
            Assert.Equal(expected, base32.Decode32());
        }

        [Theory]
        [InlineData(new byte[] { }, "=")]
        [InlineData(new byte[] { }, "==")]
        [InlineData(new byte[] { }, "===")]
        [InlineData(new byte[] { }, "====")]
        [InlineData(new byte[] { }, "=====")]
        [InlineData(new byte[] { 0x66 }, "MY=")]
        [InlineData(new byte[] { 0x66 }, "MY==")]
        [InlineData(new byte[] { 0x66 }, "MY===")]
        [InlineData(new byte[] { 0x66 }, "MY====")]
        [InlineData(new byte[] { 0x66 }, "MY=====")]
        [InlineData(new byte[] { 0x66 }, "MY=========")]
        public void String_Decode32_decodes_incorrectly_padded_base32(byte[] expected, string base32)
        {
            Assert.Equal(expected, base32.Decode32());
        }

        [Theory]
        [InlineData("0")]
        [InlineData("1")]
        [InlineData("8")]
        [InlineData("9")]
        [InlineData("!")]
        [InlineData("MZXQ!")]
        [InlineData("!@#$%^&*()")]
        [InlineData("MY======MY")]
        [InlineData("MY======MY======")]
        [InlineData("=MY======")]
        public void String_Decode32_throws_on_invalid_base32(string invalidBase32)
        {
            Exceptions.AssertThrowsInternalError(() => invalidBase32.Decode32(), "invalid characters in base32");
        }

        [Theory]
        [InlineData(new byte[] { }, "")]
        [InlineData(new byte[] { 0x61 }, "YQ==")]
        [InlineData(new byte[] { 0x61, 0x62 }, "YWI=")]
        [InlineData(new byte[] { 0x61, 0x62, 0x63 }, "YWJj")]
        [InlineData(new byte[] { 0x61, 0x62, 0x63, 0x64 }, "YWJjZA==")]
        public void String_Decode64_decodes_base64(byte[] expected, string base64)
        {
            Assert.Equal(expected, base64.Decode64());
        }

        [Theory]
        [InlineData(new byte[] { 0xFB, 0xEF, 0xFF }, "++__")]
        [InlineData(new byte[] { 0xFB, 0xEF, 0xFF }, "+-_/")]
        [InlineData(new byte[] { 0xFB, 0xEF, 0xBE }, "++--")]
        [InlineData(new byte[] { 0xF9, 0xAF, 0xDC }, "+a_c")]
        public void String_Decode64UrlSafe_decodes_url_safe_base64(byte[] expected, string base64)
        {
            Assert.Equal(expected, base64.Decode64UrlSafe());
        }

        [Theory]
        [InlineData(new byte[] { }, "")]
        [InlineData(new byte[] { 0x61 }, "YQ")]
        [InlineData(new byte[] { 0x61, 0x62 }, "YWI")]
        [InlineData(new byte[] { 0x61, 0x62, 0x63 }, "YWJj")]
        [InlineData(new byte[] { 0x61, 0x62, 0x63, 0x64 }, "YWJjZA")]
        public void String_Decode64Loose_decodes_base64_without_padding(byte[] expected, string base64)
        {
            Assert.Equal(expected, base64.Decode64Loose());
        }

        [Theory]
        [InlineData(new byte[] { }, "==")]
        [InlineData(new byte[] { 0x61 }, "YQ=")]
        [InlineData(new byte[] { 0x61, 0x62 }, "YWI==")]
        [InlineData(new byte[] { 0x61, 0x62, 0x63 }, "YWJj=")]
        [InlineData(new byte[] { 0x61, 0x62, 0x63, 0x64 }, "YWJjZA===")]
        public void String_Decode64Loose_decodes_incorrectly_padded_base64(byte[] expected, string base64)
        {
            Assert.Equal(expected, base64.Decode64Loose());
        }

        [Theory]
        [InlineData(0, "")]
        [InlineData(0, "0")]
        [InlineData(255, "0FF")]
        [InlineData(0xDEADBEEF, "0DEADBEEF")]
        public void String_ToBigInt_returns_BigInteger(uint number, string str)
        {
            Assert.Equal(new BigInteger(number), str.ToBigInt());
        }

        [Theory]
        [InlineData(127, "7F")]
        [InlineData(128, "80")]
        [InlineData(255, "FF")]
        [InlineData(0xDEADBEEF, "DEADBEEF")]
        public void String_ToBigInt_returns_positive_BigInteger(uint number, string str)
        {
            Assert.Equal(new BigInteger(number), str.ToBigInt());
        }

        [Theory]
        [InlineData("x", 0, "")]
        [InlineData("x", 1, "x")]
        [InlineData("x", 2, "xx")]
        [InlineData("x", 3, "xxx")]
        [InlineData("xyz", 0, "")]
        [InlineData("xyz", 1, "xyz")]
        [InlineData("xyz", 2, "xyzxyz")]
        [InlineData("xyz", 3, "xyzxyzxyz")]
        public void String_Repeat_returns_repeated_string(string s, int times, string expected)
        {
            Assert.Equal(expected, s.Repeat(times));
        }

        //
        // StringBuilder
        //

        [Theory]
        [InlineData("", "", "\n")]
        [InlineData("init-", "line2", "init-line2\n")]
        [InlineData("\r", "\r", "\r\r\n")]
        [InlineData("\r\n", "\r\n", "\r\n\r\n\n")]
        public void StringBuilder_AppendLineLf_appends_line_with_lf(string a, string b, string expected)
        {
            var s = new StringBuilder(a).AppendLineLf(b).ToString();
            Assert.Equal(expected, s);
        }

        //
        // byte[]
        //

        [Theory]
        [InlineData(null)]
        [InlineData(new byte[0])]
        public void ByteArray_IsNullOrEmpty_returns_true_for_null_and_empty_array(byte[] bytes)
        {
            Assert.True(bytes.IsNullOrEmpty());
        }

        [Theory]
        [InlineData(new byte[] { 13 })]
        [InlineData(new byte[] { 13, 37 })]
        [InlineData(new byte[] { 1, 3, 3, 7 })]
        public void ByteArray_IsNullOrEmpty_returns_false_for_non_empty_array(byte[] bytes)
        {
            Assert.False(bytes.IsNullOrEmpty());
        }

        [Fact]
        public void ByteArray_ToUtf8_returns_string()
        {
            Assert.Equal("", new byte[] { }.ToUtf8());
            Assert.Equal(TestString, TestBytes.ToUtf8());
        }

        [Fact]
        public void ByteArray_ToHex_returns_hex_string()
        {
            Assert.Equal("", new byte[] { }.ToHex());
            Assert.Equal(TestHex, TestBytes.ToHex());
        }

        [Theory]
        [InlineData("", new byte[] { })]
        [InlineData("+w==", new byte[] { 0xFB })]
        [InlineData("++8=", new byte[] { 0xFB, 0xEF })]
        [InlineData("++//", new byte[] { 0xFB, 0xEF, 0xFF })]
        public void ByteArray_ToBase64_returns_regular_base64_with_padding(string expected, byte[] bytes)
        {
            Assert.Equal(expected, bytes.ToBase64());
        }

        [Theory]
        [InlineData("", new byte[] { })]
        [InlineData("-w==", new byte[] { 0xFB })]
        [InlineData("--8=", new byte[] { 0xFB, 0xEF })]
        [InlineData("--__", new byte[] { 0xFB, 0xEF, 0xFF })]
        public void ByteArray_ToUrlSafeBase64_returns_urlsafe_base64_with_padding(string expected, byte[] bytes)
        {
            Assert.Equal(expected, bytes.ToUrlSafeBase64());
        }

        [Theory]
        [InlineData("", new byte[] { })]
        [InlineData("-w", new byte[] { 0xFB })]
        [InlineData("--8", new byte[] { 0xFB, 0xEF })]
        [InlineData("--__", new byte[] { 0xFB, 0xEF, 0xFF })]
        public void ByteArray_ToUrlSafeBase64NoPadding_returns_urlsafe_base64_without_padding(string expected, byte[] bytes)
        {
            Assert.Equal(expected, bytes.ToUrlSafeBase64NoPadding());
        }

        [Theory]
        [InlineData(0, new byte[] { })]
        [InlineData(0, new byte[] { 0 })]
        [InlineData(255, new byte[] { 0xFF })]
        [InlineData(0xDEADBEEF, new byte[] { 0xDE, 0xAD, 0xBE, 0xEF })]
        public void ByteArray_ToBigInt_returns_BigInteger(uint number, byte[] bytes)
        {
            Assert.Equal(new BigInteger(number), bytes.ToBigInt());
        }

        [Fact]
        public void ByteArray_Open_provides_binary_read()
        {
            byte result = 0;
            new byte[] { 13 }.Open(reader => result = reader.ReadByte());

            Assert.Equal(13, result);
        }

        [Fact]
        public void ByteArray_Open_returns_result()
        {
            byte result = new byte[] { 13 }.Open(reader => reader.ReadByte());

            Assert.Equal(13, result);
        }

        [Theory]
        // Subarrays at 0, no overflow
        [InlineData(0, 1, "0")]
        [InlineData(0, 2, "01")]
        [InlineData(0, 3, "012")]
        [InlineData(0, 15, "0123456789abcde")]
        [InlineData(0, 16, "0123456789abcdef")]
        // Subarrays in the middle, no overflow
        [InlineData(1, 1, "1")]
        [InlineData(3, 2, "34")]
        [InlineData(8, 3, "89a")]
        [InlineData(15, 1, "f")]
        // Subarrays of zero length, no overflow
        [InlineData(0, 0, "")]
        [InlineData(1, 0, "")]
        [InlineData(9, 0, "")]
        [InlineData(15, 0, "")]
        // Subarrays at 0 with overflow
        [InlineData(0, 17, "0123456789abcdef")]
        [InlineData(0, 12345, "0123456789abcdef")]
        [InlineData(0, int.MaxValue, "0123456789abcdef")]
        // Subarrays in the middle with overflow
        [InlineData(1, 16, "123456789abcdef")]
        [InlineData(1, 12345, "123456789abcdef")]
        [InlineData(8, 9, "89abcdef")]
        [InlineData(8, 67890, "89abcdef")]
        [InlineData(15, 2, "f")]
        [InlineData(15, int.MaxValue, "f")]
        // Subarrays beyond the end
        [InlineData(16, 0, "")]
        [InlineData(16, 1, "")]
        [InlineData(16, 16, "")]
        [InlineData(16, int.MaxValue, "")]
        [InlineData(12345, 0, "")]
        [InlineData(12345, 1, "")]
        [InlineData(12345, 56789, "")]
        [InlineData(12345, int.MaxValue, "")]
        [InlineData(int.MaxValue, 0, "")]
        [InlineData(int.MaxValue, 1, "")]
        [InlineData(int.MaxValue, 12345, "")]
        [InlineData(int.MaxValue, int.MaxValue, "")]
        public void ByteArray_Sub_returns_subarray(int start, int length, string expected)
        {
            var array = "0123456789abcdef".ToBytes();
            Assert.Equal(expected.ToBytes(), array.Sub(start, length));
        }

        [Fact]
        public void ByteArray_Sub_throws_on_negative_length()
        {
            Exceptions.AssertThrowsInternalError(() => new byte[] { }.Sub(0, -1337), "length should not be negative");
        }

        //
        // DateTime
        //

        [Fact]
        public void DateTime_UnixSeconds_returns_number_of_seconds_since_epoch()
        {
            Assert.Equal(1493456789U, new DateTime(2017, 4, 29, 9, 6, 29, DateTimeKind.Utc).UnixSeconds());
        }

        //
        // Dictionary
        //

        [Fact]
        public void Dictionary_GetOrDefault_returns_value_when_present()
        {
            var dictionary = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };

            Assert.Equal("1", dictionary.GetOrDefault("one", "13"));
            Assert.Equal("2", dictionary.GetOrDefault("two", "13"));
        }

        [Fact]
        public void Dictionary_GetOrDefault_returns_default_value_when_not_present()
        {
            var emptyDictionary = new Dictionary<string, string>();
            var dictionary = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };

            Assert.Equal("13", emptyDictionary.GetOrDefault("three", "13"));
            Assert.Equal("13", dictionary.GetOrDefault("three", "13"));
        }

        [Fact]
        public void Dictionary_GetOrAdd_value_when_present()
        {
            var dictionary = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };

            Assert.Equal("1", dictionary.GetOrAdd("one", () => "13"));
            Assert.Equal("2", dictionary.GetOrAdd("two", () => "13"));
        }

        [Fact]
        public void Dictionary_GetOrAdd_inserts_new_value_when_not_present()
        {
            var emptyDictionary = new Dictionary<string, string>();
            var dictionary = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };

            Assert.Equal("13", emptyDictionary.GetOrAdd("three", () => "13"));
            Assert.Equal("13", emptyDictionary["three"]);

            Assert.Equal("13", dictionary.GetOrAdd("three", () => "13"));
            Assert.Equal("13", dictionary["three"]);
        }

        [Fact]
        public void Dictionary_MergeCopy_merges_empty_dictionaries_to_new_dictionary()
        {
            var e1 = new Dictionary<string, string>();
            var e2 = new Dictionary<string, string>();
            var m = e1.MergeCopy(e2);

            Assert.Empty(m);
            Assert.NotSame(e1, m);
            Assert.NotSame(e2, m);
        }

        [Fact]
        public void Dictionary_MergeCopy_merges_empty_and_non_empty_dictionary_to_new_dictionary()
        {
            var e = new Dictionary<string, string>();
            var d = new Dictionary<string, string>() { { "one", "1" }, { "two", "2" } };
            var ed = e.MergeCopy(d);
            var de = d.MergeCopy(e);

            Assert.Equal(d, ed);
            Assert.Equal(d, de);
            Assert.NotSame(d, ed);
            Assert.NotSame(d, de);
        }

        [Fact]
        public void Dictionary_MergeCopy_merges_non_overlapping_dictionaries()
        {
            var d1 = new Dictionary<string, string>() { { "one", "1" }, { "two", "2" } };
            var d2 = new Dictionary<string, string>() { { "three", "3" }, { "four", "4" } };
            var r = new Dictionary<string, string>()
            {
                { "one", "1" },
                { "two", "2" },
                { "three", "3" },
                { "four", "4" },
            };

            Assert.Equal(r, d1.MergeCopy(d2));
            Assert.Equal(r, d2.MergeCopy(d1));
        }

        [Fact]
        public void Dictionary_MergeCopy_merges_overlapping_dictionaries()
        {
            var d1 = new Dictionary<string, string>() { { "one", "1" }, { "two", "2" } };
            var d2 = new Dictionary<string, string>() { { "three", "3" }, { "two", "2!" } };

            var r12 = d1.MergeCopy(d2);
            var r21 = d2.MergeCopy(d1);

            Assert.Equal(3, r12.Count);
            Assert.Equal(3, r21.Count);

            Assert.Equal("1", r12["one"]);
            Assert.Equal("1", r21["one"]);

            Assert.Equal("2!", r12["two"]);
            Assert.Equal("2", r21["two"]);

            Assert.Equal("3", r12["three"]);
            Assert.Equal("3", r21["three"]);
        }

        [Fact]
        public void Dictionary_Merge_returns_left_when_right_is_empty()
        {
            var left = new Dictionary<string, string>() { { "one", "1" }, { "two", "2" } };
            var right = new Dictionary<string, string>();

            Assert.Same(left, left.Merge(right));
        }

        [Fact]
        public void Dictionary_Merge_returns_right_when_left_is_empty()
        {
            var left = new Dictionary<string, string>();
            var right = new Dictionary<string, string>() { { "one", "1" }, { "two", "2" } };

            Assert.Same(right, left.Merge(right));
        }

        [Fact]
        public void Dictionary_Merge_returns_left_when_both_are_empty()
        {
            var left = new Dictionary<string, string>();
            var right = new Dictionary<string, string>();

            Assert.Same(left, left.Merge(right));
        }

        //
        // IEnumerable
        //

        [Theory]
        [InlineData("", "")]
        [InlineData("a", "", "a")]
        [InlineData("ab", "", "a", "b")]
        [InlineData("", "-")]
        [InlineData("a", "-", "a")]
        [InlineData("a-b", "-", "a", "b")]
        [InlineData("1-2", "-", 1, 2)]
        public void IEnumerable_JoinToString_returns_joined_string(string expected, string separator, params object[] objects)
        {
            Assert.Equal(expected, objects.JoinToString(separator));
        }

        //
        // BigInteger
        //

        [Theory]
        [InlineData("0", 0)]
        [InlineData("1", 1)]
        [InlineData("d", 0xD)]
        [InlineData("de", 0xDE)]
        [InlineData("dea", 0xDEA)]
        [InlineData("dead", 0xDEAD)]
        [InlineData("80", 0x80)]
        [InlineData("ff", 0xFF)]
        [InlineData("-1", -1)]
        [InlineData("-d", -0xD)]
        [InlineData("-de", -0xDE)]
        [InlineData("-dea", -0xDEA)]
        [InlineData("-dead", -0xDEAD)]
        [InlineData("-80", -0x80)]
        [InlineData("-ff", -0xFF)]
        public void BigInteger_ToHex_returns_hex_string(string hex, int number)
        {
            Assert.Equal(hex, new BigInteger(number).ToHex());
        }

        [Theory]
        [InlineData(3, -3, 3, 10)]
        [InlineData(36, -4, 3, 100)]
        [InlineData(936, -4, 3, 1000)]
        [InlineData(594327, -1337, 19, 1000000)]
        public void BigInteger_ModExp_returns_positive_result(int result, int b, int e, int m)
        {
            Assert.Equal(new BigInteger(result), new BigInteger(b).ModExp(new BigInteger(e), new BigInteger(m)));
        }

        //
        // Stream
        //

        [Theory]
        [InlineData(new byte[] { })]
        [InlineData(new byte[] { 1 })]
        [InlineData(new byte[] { 1, 2 })]
        [InlineData(new byte[] { 1, 2, 3 })]
        [InlineData(new byte[] { 1, 2, 3, 4 })]
        public void Stream_ReadAll_reads_all_bytes_from_stream(byte[] bytes)
        {
            var bufferSizes = new int[] { 1, 2, 3, 4, 100, 1024, 1337, 65536 };

            // Default buffer
            Assert.Equal(bytes, new MemoryStream(bytes).ReadAll());

            // Custom buffer size
            foreach (var size in bufferSizes)
                Assert.Equal(bytes, new MemoryStream(bytes).ReadAll(size));
        }

        [Theory]
        [InlineData(0)]
        [InlineData(-1)]
        [InlineData(-1337)]
        public void Stream_ReadAll_throws_on_zero_buffer_size(int size)
        {
            Exceptions.AssertThrowsInternalError(() => new MemoryStream().ReadAll(size), "Buffer size must be positive");
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(7)]
        [InlineData(13)]
        [InlineData(42)]
        [InlineData(1337)]
        public void Stream_ReadExact_reads_exact_size(int size)
        {
            var s = new TrickleStream(13);
            var b = s.ReadExact(size);

            Assert.Equal(size, b.Length);
        }

        [Fact]
        public void Stream_ReadExact_throws_when_too_little_data_available()
        {
            var s = new MemoryStream(new byte[10], writable: false);
            Exceptions.AssertThrowsInternalError(() => s.ReadExact(13), "Failed to read 13 bytes from the stream");
        }

        [Theory]
        [InlineData(0, 0, "---")]
        [InlineData(0, 1, "*--")]
        [InlineData(0, 2, "**-")]
        [InlineData(0, 3, "***")]
        [InlineData(1, 0, "---")]
        [InlineData(1, 1, "-*-")]
        [InlineData(1, 2, "-**")]
        [InlineData(2, 0, "---")]
        [InlineData(2, 1, "--*")]
        public void Stream_ReadExact_with_range_reads_bytes(int start, int size, string expected)
        {
            var s = new MemoryStream("*".Repeat(10).ToBytes(), writable: false);
            var b = "-".Repeat(3).ToBytes();
            s.ReadExact(b, start, size);

            Assert.Equal(expected.ToBytes(), b);
        }

        [Theory]
        [InlineData(0, 6)]
        [InlineData(1, 5)]
        [InlineData(2, 4)]
        [InlineData(3, 3)]
        [InlineData(4, 2)]
        [InlineData(5, 1)]
        [InlineData(6, 0)]
        public void Stream_ReadExact_with_range_throws_on_too_short_buffer(int start, int size)
        {
            var s = new MemoryStream(new byte[10], writable: false);
            var b = new byte[5];

            Exceptions.AssertThrowsInternalError(() => s.ReadExact(b, start, size), "The buffer is too small");
        }

        [Fact]
        public void Stream_TrySkip_skips_seekable_stream()
        {
            var s = new SeekOnlyStream();

            Assert.True(s.TrySkip(100));
            Assert.Equal(100, s.Position);
        }

        [Fact]
        public void Stream_TrySkip_skips_non_seekable_stream()
        {
            var s = new TrickleStream(13);

            Assert.True(s.TrySkip(100));
            Assert.Equal(100, s.Position);
        }

        [Fact]
        public void Stream_TrySkip_returns_false_on_short_stream()
        {
            var s = new TrickleStream(13, 100);
            Assert.False(s.TrySkip(101));
        }

        //
        // BinaryReader
        //

        [Fact]
        public void BinaryReader_ReadUInt16BigEndian_reads_ushort()
        {
            var bytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF };
            using var s = new MemoryStream(bytes);
            using var r = new BinaryReader(s);

            Assert.Equal(0xDEAD, r.ReadUInt16BigEndian());
            Assert.Equal(0xBEEF, r.ReadUInt16BigEndian());
        }

        [Fact]
        public void BinaryReader_ReadUInt32BigEndian_reads_uint()
        {
            var bytes = new byte[] { 0xDE, 0xAD, 0xBE, 0xEF, 0xFE, 0xED, 0xF0, 0x0D };
            using var s = new MemoryStream(bytes);
            using var r = new BinaryReader(s);

            Assert.Equal(0xDEADBEEF, r.ReadUInt32BigEndian());
            Assert.Equal(0xFEEDF00D, r.ReadUInt32BigEndian());
        }

        //
        // JToken
        //

        //
        // JToken.StringAt
        //

        [Fact]
        public void JToken_StringAt_returns_string()
        {
            var j = JObject.Parse(
                """
                {
                    "k1": "v1",
                    "k2": "v2",
                    "k3": "v3"
                }
                """
            );

            Assert.Equal("v1", j.StringAt("k1", ""));
            Assert.Equal("v2", j.StringAt("k2", ""));
            Assert.Equal("v3", j.StringAt("k3", ""));
        }

        [Theory]
        [InlineData("null")]
        [InlineData("true")]
        [InlineData("10")]
        [InlineData("10.0")]
        [InlineData("[]")]
        [InlineData("{}")]
        public void JToken_StringAt_returns_default_value_on_non_string(string value)
        {
            var j = JObject.Parse($$"""{"key": {{value}}}""");

            Assert.Equal("yo", j.StringAt("key", "yo"));
        }

        [Fact]
        public void JToken_StringAt_returns_default_value_when_field_does_not_exist()
        {
            var j = JObject.Parse("""{"key": "value"}""");

            Assert.Equal("yo", j.StringAt("not-a-key", "yo"));
        }

        [Fact]
        public void JToken_StringAt_returns_default_value_when_token_is_null()
        {
            Assert.Equal("yo", (null as JToken).StringAt("key", "yo"));
        }

        //
        // JToken.IntAt
        //

        [Fact]
        public void JToken_IntAt_returns_int()
        {
            var j = JObject.Parse(
                """
                {
                    "k1": 13,
                    "k2": 17,
                    "k3": 19
                }
                """
            );

            Assert.Equal(13, j.IntAt("k1", 0));
            Assert.Equal(17, j.IntAt("k2", 0));
            Assert.Equal(19, j.IntAt("k3", 0));
        }

        [Theory]
        [InlineData("null")]
        [InlineData("true")]
        [InlineData("\"10\"")]
        [InlineData("10.0")]
        [InlineData("[]")]
        [InlineData("{}")]
        public void JToken_IntAt_returns_default_value_on_non_ints(string value)
        {
            var j = JObject.Parse($$"""{"key": {{value}}}""");

            Assert.Equal(1337, j.IntAt("key", 1337));
        }

        [Fact]
        public void JToken_IntAt_returns_default_value_when_field_does_not_exist()
        {
            var j = JObject.Parse("""{"key": "value"}""");

            Assert.Equal(1337, j.IntAt("not-a-key", 1337));
        }

        [Fact]
        public void JToken_IntAt_returns_default_value_when_token_is_null()
        {
            Assert.Equal(1337, (null as JToken).IntAt("key", 1337));
        }

        //
        // JToken.BoolAt
        //

        [Fact]
        public void JToken_BoolAt_returns_bools()
        {
            var j = JObject.Parse(
                """
                {
                    "k1": true,
                    "k2": false,
                    "k3": true
                }
                """
            );

            Assert.True(j.BoolAt("k1", false));
            Assert.False(j.BoolAt("k2", true));
            Assert.True(j.BoolAt("k3", false));
        }

        [Theory]
        [InlineData("null")]
        [InlineData("\"true\"")]
        [InlineData("10")]
        [InlineData("10.0")]
        [InlineData("[]")]
        [InlineData("{}")]
        public void JToken_BoolAt_returns_default_value_on_non_bools(string value)
        {
            var j = JObject.Parse($$"""{"key": {{value}}}""");

            Assert.False(j.BoolAt("key", false));
            Assert.True(j.BoolAt("key", true));
        }

        [Fact]
        public void JToken_BoolAt_returns_default_value_when_field_does_not_exist()
        {
            var j = JObject.Parse("""{"key": "value"}""");

            Assert.False(j.BoolAt("not-a-key", false));
            Assert.True(j.BoolAt("not-a-key", true));
        }

        [Fact]
        public void JToken_BoolAt_returns_default_value_when_token_is_null()
        {
            Assert.False((null as JToken).BoolAt("key", false));
            Assert.True((null as JToken).BoolAt("key", true));
        }

        //
        // JToken.ArrayAt
        //

        [Fact]
        public void JToken_ArrayAt_returns_array()
        {
            var j = JToken.Parse("""{"a": [1]}""");

            Assert.NotEmpty(j.ArrayAt("a", null));
            Assert.NotEmpty(j.ArrayAtOrEmpty("a"));
        }

        [Theory]
        [InlineData("null")]
        [InlineData("true")]
        [InlineData("10")]
        [InlineData("10.0")]
        [InlineData("\"[]\"")]
        [InlineData("{}")]
        public void JToken_ArrayAt_returns_default_value_on_non_arrays(string value)
        {
            var j = JObject.Parse($$"""{"key": {{value}}}""");
            var a = JArray.Parse("[1, 2, 3]");

            Assert.Same(a, j.ArrayAt("key", a));
            Assert.Null(j.ArrayAt("key", null));
            Assert.Empty(j.ArrayAtOrEmpty("key"));
        }

        [Fact]
        public void JToken_ArrayAt_returns_default_value_when_field_does_not_exist()
        {
            var j = JObject.Parse("""{"key": []}""");
            var a = JArray.Parse("[1, 2, 3]");

            Assert.Same(a, j.ArrayAt("not-a-key", a));
            Assert.Null(j.ArrayAt("not-a-key", null));
            Assert.Empty(j.ArrayAtOrEmpty("not-a-key"));
        }

        [Fact]
        public void JToken_ArrayAt_returns_default_value_when_token_is_null()
        {
            var a = JArray.Parse("[1, 2, 3]");

            Assert.Same(a, ((JToken)null).ArrayAt("key", a));
            Assert.Null(((JToken)null).ArrayAt("key", null));
            Assert.Empty(((JToken)null).ArrayAtOrEmpty("key"));
        }

        //
        // JToken.ObjectAt
        //

        [Fact]
        public void JToken_ObjectAt_returns_object()
        {
            var j = JToken.Parse("""{"a": {"b": 1}}""");

            Assert.NotEmpty(j.ObjectAt("a", null));
            Assert.NotEmpty(j.ObjectAtOrEmpty("a"));
        }

        [Theory]
        [InlineData("null")]
        [InlineData("true")]
        [InlineData("10")]
        [InlineData("10.0")]
        [InlineData("[]")]
        [InlineData("\"{}\"")]
        public void JToken_ObjectAt_returns_default_value_on_non_objects(string value)
        {
            var j = JObject.Parse($$"""{"key": {{value}}}""");
            var o = JObject.Parse("""{"a": 1, "b": 2, "c": 3}""");

            Assert.Same(o, j.ObjectAt("key", o));
            Assert.Null(j.ObjectAt("key", null));
            Assert.Empty(j.ObjectAtOrEmpty("key"));
        }

        [Fact]
        public void JToken_ObjectAt_returns_default_value_when_field_does_not_exist()
        {
            var j = JObject.Parse("""{"key": {}}""");
            var o = JObject.Parse("""{"a": 1, "b": 2, "c": 3}""");

            Assert.Same(o, j.ObjectAt("not-a-key", o));
            Assert.Null(j.ObjectAt("not-a-key", null));
            Assert.Empty(j.ObjectAtOrEmpty("not-a-key"));
        }

        [Fact]
        public void JToken_ObjectAt_returns_default_value_when_token_is_null()
        {
            var o = JObject.Parse("""{"a": 1, "b": 2, "c": 3}""");

            Assert.Same(o, ((JToken)null).ObjectAt("key", o));
            Assert.Null(((JToken)null).ObjectAt("key", null));
            Assert.Empty(((JToken)null).ObjectAtOrEmpty("key"));
        }

        //
        // JToken.*
        //

        [Fact]
        public void JToken_At_functions_work_on_nested_objects()
        {
            var j = JObject.Parse(
                """
                {
                    "k1": "v1",
                    "k2": {"k22": 1337},
                    "k3": {"k33": {"k333": false}}
                }
                """
            );

            Assert.Equal("yo", j["not-a-key"].StringAt("key", "yo"));
            Assert.Equal(1337, j["k2"].IntAt("k22", 0));
        }

        [Theory]
        [InlineData("null")]
        [InlineData("true")]
        [InlineData("10")]
        [InlineData("10.0")]
        [InlineData("\"string\"")]
        [InlineData("[]")]
        public void JToken_At_functions_return_default_value_when_token_is_not_an_object(string json)
        {
            var j = JToken.Parse(json);
            var a = JArray.Parse("[1, 2, 3]");
            var o = JObject.Parse("""{"a": 1, "b": 2, "c": 3}""");

            Assert.Equal("yo", j.StringAt("key", "yo"));
            Assert.Equal(1337, j.IntAt("key", 1337));
            Assert.True(j.BoolAt("key", true));
            Assert.Same(a, j.ArrayAt("key", a));
            Assert.Empty(j.ArrayAtOrEmpty("key"));
            Assert.Same(o, j.ObjectAt("key", o));
            Assert.Empty(j.ObjectAtOrEmpty("key"));
        }

        //
        // CookieContainer
        //

        [Fact]
        public void CookieContainer_Clear_removes_all_cookies()
        {
            // Arrange
            var c = new CookieContainer();
            c.Add(new Uri("http://example1.com"), new Cookie("key1", "value1"));
            c.Add(new Uri("http://example1.com"), new Cookie("key2", "value2"));
            c.Add(new Uri("http://example2.com"), new Cookie("key3", "value3"));
            c.Add(new Uri("http://example3.com"), new Cookie("key4", "value4"));

            // Act/Assert
            c.GetAllCookies().Count.ShouldBe(4);
            c.Clear();
            c.GetAllCookies().ShouldBeEmpty();
        }

        private class TrickleStream : Stream
        {
            public override bool CanRead => true;
            public override bool CanSeek => false;
            public override bool CanWrite => false;
            public override long Position { get; set; }

            public TrickleStream(int portion, int length = Int32.MaxValue)
            {
                _portion = portion;
                _length = length;
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                var size = Math.Min(Math.Min(_portion, count), _length - (int)Position);
                for (var i = 0; i < size; i++)
                    buffer[offset + i] = 0xCC;
                Position += size;

                return size;
            }

            public override void Flush() => throw new NotImplementedException();

            public override long Seek(long offset, SeekOrigin origin) => throw new NotImplementedException();

            public override void SetLength(long value) => throw new NotImplementedException();

            public override void Write(byte[] buffer, int offset, int count) => throw new NotImplementedException();

            public override long Length => throw new NotImplementedException();

            private int _portion;
            private int _length;
        }

        private class SeekOnlyStream : Stream
        {
            public override bool CanRead => false;
            public override bool CanSeek => true;
            public override bool CanWrite => false;
            public override long Position { get; set; }

            public override long Seek(long offset, SeekOrigin origin)
            {
                if (origin != SeekOrigin.Current)
                    throw new NotImplementedException();

                Position += offset;
                return Position;
            }

            public override void Flush() => throw new NotImplementedException();

            public override int Read(byte[] buffer, int offset, int count) => throw new NotImplementedException();

            public override void SetLength(long value) => throw new NotImplementedException();

            public override void Write(byte[] buffer, int offset, int count) => throw new NotImplementedException();

            public override long Length => throw new NotImplementedException();
        }

        //
        // Data
        //

        private const string TestString = "All your base are belong to us";
        private const string TestHex = "416c6c20796f75722062617365206172652062656c6f6e6720746f207573";

        private static readonly byte[] TestBytes =
        {
            65,
            108,
            108,
            32,
            121,
            111,
            117,
            114,
            32,
            98,
            97,
            115,
            101,
            32,
            97,
            114,
            101,
            32,
            98,
            101,
            108,
            111,
            110,
            103,
            32,
            116,
            111,
            32,
            117,
            115,
        };
    }
}
