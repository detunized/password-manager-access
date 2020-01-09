// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Numerics;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class ExtensionsTest
    {
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
        [InlineData("", new byte[] { })]
        [InlineData("00", new byte[] { 0 })]
        [InlineData("00ff", new byte[] { 0, 255 })]
        [InlineData("00010203040506070809", new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 })]
        [InlineData("000102030405060708090a0b0c0d0e0f",
                    new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 })]
        [InlineData("8af633933e96a3c3550c2734bd814195",
                    new byte[] { 0x8A, 0xF6, 0x33, 0x93, 0x3E, 0x96, 0xA3, 0xC3,
                                 0x55, 0x0C, 0x27, 0x34, 0xBD, 0x81, 0x41, 0x95 })]
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

        //
        // byte[]
        //

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
        public void ByteArray_ToUrlSafeBase64NoPadding_returns_urlsafe_base64_without_padding(string expected,
                                                                                              byte[] bytes)
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
            new byte[] {13}.Open(reader => result = reader.ReadByte());

            Assert.Equal(13, result);
        }

        [Fact]
        public void ByteArray_Open_returns_result()
        {
            byte result = new byte[] {13}.Open(reader => reader.ReadByte());

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
            Exceptions.AssertThrowsInternalError(() => new byte[] { }.Sub(0, -1337),
                                                 "length should not be negative");
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
        public void Dictionary_GetOrDefault_returns_default_value_when_not_present_present()
        {
            var emptyDictionary = new Dictionary<string, string>();
            var dictionary = new Dictionary<string, string> { { "one", "1" }, { "two", "2" } };

            Assert.Equal("13", emptyDictionary.GetOrDefault("three", "13"));
            Assert.Equal("13", dictionary.GetOrDefault("three", "13"));
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
            var r = new Dictionary<string, string>() { { "one", "1" }, { "two", "2" }, { "three", "3" }, { "four", "4" } };

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
        public void IEnumerable_JoinToString_returns_joined_string(string expected,
                                                                   string separator,
                                                                   params object[] objects)
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
            Assert.Equal(new BigInteger(result),
                         new BigInteger(b).ModExp(new BigInteger(e), new BigInteger(m)));
        }

        //
        // Data
        //

        private const string TestString = "All your base are belong to us";
        public const string TestHex = "416c6c20796f757220626173652061" +
                                      "72652062656c6f6e6720746f207573";

        private static readonly byte[] TestBytes =
        {
            65, 108, 108, 32, 121, 111, 117, 114, 32, 98, 97, 115, 101, 32, 97,
            114, 101, 32, 98, 101, 108, 111, 110, 103, 32, 116, 111, 32, 117, 115
        };

        private static readonly Dictionary<string, byte[]> HexToBytes = new Dictionary<string, byte[]>
        {
            {"",
             new byte[] {}},

            {"00",
             new byte[] {0}},

            {"00ff",
             new byte[] {0, 255}},

            {"00010203040506070809",
             new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},

            {"000102030405060708090a0b0c0d0e0f",
             new byte[] {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}},

            {"8af633933e96a3c3550c2734bd814195",
             new byte[] {0x8A, 0xF6, 0x33, 0x93, 0x3E, 0x96, 0xA3, 0xC3, 0x55, 0x0C, 0x27, 0x34, 0xBD, 0x81, 0x41, 0x95}}
        };
    }
}
