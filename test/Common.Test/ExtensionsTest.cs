// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Numerics;
using Xunit;

namespace PasswordManagerAccess.Common.Test
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

        [Fact]
        public void String_DecodeHex()
        {
            foreach (var i in HexToBytes)
            {
                Assert.Equal(i.Value, i.Key.ToLower().DecodeHex());
                Assert.Equal(i.Value, i.Key.ToUpper().DecodeHex());
            }
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

        [Fact]
        public void String_Decode32_decodes_base32()
        {
            // Test vectors from https://tools.ietf.org/html/rfc4648#section-10
            Assert.Equal(new byte[] { }, "".Decode32());
            Assert.Equal(new byte[] { 0x66 }, "MY======".Decode32());
            Assert.Equal(new byte[] { 0x66 }, "MY======".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f }, "MZXQ====".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f }, "MZXW6===".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f, 0x62 }, "MZXW6YQ=".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61 }, "MZXW6YTB".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }, "MZXW6YTBOI======".Decode32());
        }

        [Fact]
        public void String_Decode32_decodes_base32_without_padding()
        {
            // Test vectors from https://tools.ietf.org/html/rfc4648#section-10
            Assert.Equal(new byte[] { 0x66 }, "MY".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f }, "MZXQ".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f }, "MZXW6".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f, 0x62 }, "MZXW6YQ".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61 }, "MZXW6YTB".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }, "MZXW6YTBOI".Decode32());
        }

        [Fact]
        public void String_Decode32_decodes_base32_lowercase()
        {
            // Test vectors from https://tools.ietf.org/html/rfc4648#section-10
            Assert.Equal(new byte[] { 0x66 }, "my".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f }, "mzxq".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f }, "mzxw6".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f, 0x62 }, "mzxw6yq".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61 }, "mzxw6ytb".Decode32());
            Assert.Equal(new byte[] { 0x66, 0x6f, 0x6f, 0x62, 0x61, 0x72 }, "mzxw6ytboi".Decode32());
        }

        [Fact]
        public void String_Decode32_decodes_incorrectly_padded_base32()
        {
            Assert.Equal(new byte[] { }, "=".Decode32());
            Assert.Equal(new byte[] { }, "==".Decode32());
            Assert.Equal(new byte[] { }, "===".Decode32());
            Assert.Equal(new byte[] { }, "====".Decode32());
            Assert.Equal(new byte[] { }, "=====".Decode32());
            Assert.Equal(new byte[] { 0x66 }, "MY=".Decode32());
            Assert.Equal(new byte[] { 0x66 }, "MY==".Decode32());
            Assert.Equal(new byte[] { 0x66 }, "MY===".Decode32());
            Assert.Equal(new byte[] { 0x66 }, "MY====".Decode32());
            Assert.Equal(new byte[] { 0x66 }, "MY=====".Decode32());
            Assert.Equal(new byte[] { 0x66 }, "MY=========".Decode32());
        }

        [Fact]
        public void String_Decode32_throws_on_invalid_base32()
        {
            var invalidBase32 = new[]
            {
                "0",
                "1",
                "8",
                "9",
                "!",
                "MZXQ!",
                "!@#$%^&*()",
                "MY======MY",
                "MY======MY======",
                "=MY======",
            };

            foreach (var i in invalidBase32)
                Exceptions.AssertThrowsInternalError(() => i.Decode32(), "invalid characters in base32");
        }

        [Fact]
        public void String_Decode64_decodes_base64()
        {
            Assert.Equal(new byte[] { }, "".Decode64());
            Assert.Equal(new byte[] { 0x61 }, "YQ==".Decode64());
            Assert.Equal(new byte[] { 0x61, 0x62 }, "YWI=".Decode64());
            Assert.Equal(new byte[] { 0x61, 0x62, 0x63 }, "YWJj".Decode64());
            Assert.Equal(new byte[] { 0x61, 0x62, 0x63, 0x64 }, "YWJjZA==".Decode64());
        }

        [Fact]
        public void String_Decode64UrlSafe_decodes_url_safe_base64()
        {
            Assert.Equal(new byte[] { 0xFB, 0xEF, 0xFF }, "++__".Decode64UrlSafe());
            Assert.Equal(new byte[] { 0xFB, 0xEF, 0xFF }, "+-_/".Decode64UrlSafe());
            Assert.Equal(new byte[] { 0xFB, 0xEF, 0xBE }, "++--".Decode64UrlSafe());
            Assert.Equal(new byte[] { 0xF9, 0xAF, 0xDC }, "+a_c".Decode64UrlSafe());
        }

        [Fact]
        public void String_Decode64Loose_decodes_base64_without_padding()
        {
            Assert.Equal(new byte[] { }, "".Decode64Loose());
            Assert.Equal(new byte[] { 0x61 }, "YQ".Decode64Loose());
            Assert.Equal(new byte[] { 0x61, 0x62 }, "YWI".Decode64Loose());
            Assert.Equal(new byte[] { 0x61, 0x62, 0x63 }, "YWJj".Decode64Loose());
            Assert.Equal(new byte[] { 0x61, 0x62, 0x63, 0x64 }, "YWJjZA".Decode64Loose());
        }

        [Fact]
        public void String_Decode64Loose_decodes_incorrectly_padded_base64()
        {
            Assert.Equal(new byte[] { }, "==".Decode64Loose());
            Assert.Equal(new byte[] { 0x61 }, "YQ=".Decode64Loose());
            Assert.Equal(new byte[] { 0x61, 0x62 }, "YWI==".Decode64Loose());
            Assert.Equal(new byte[] { 0x61, 0x62, 0x63 }, "YWJj=".Decode64Loose());
            Assert.Equal(new byte[] { 0x61, 0x62, 0x63, 0x64 }, "YWJjZA===".Decode64Loose());
        }

        [Fact]
        public void String_ToBigInt_returns_BigInteger()
        {
            Assert.Equal(BigInteger.Zero, "".ToBigInt());
            Assert.Equal(BigInteger.Zero, "0".ToBigInt());
            Assert.Equal(new BigInteger(255), "0FF".ToBigInt());
            Assert.Equal(new BigInteger(0xDEADBEEF), "0DEADBEEF".ToBigInt());
        }

        [Fact]
        public void String_ToBigInt_returns_positive_BigInteger()
        {
            Assert.Equal(new BigInteger(127), "7F".ToBigInt());
            Assert.Equal(new BigInteger(128), "80".ToBigInt());
            Assert.Equal(new BigInteger(255), "FF".ToBigInt());
            Assert.Equal(new BigInteger(0xDEADBEEF), "DEADBEEF".ToBigInt());
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

        [Fact]
        public void ByteArray_ToBase64_returns_regular_base64_with_padding()
        {
            Assert.Equal("", new byte[] { }.ToBase64());
            Assert.Equal("+w==", new byte[] { 0xFB }.ToBase64());
            Assert.Equal("++8=", new byte[] { 0xFB, 0xEF }.ToBase64());
            Assert.Equal("++//", new byte[] { 0xFB, 0xEF, 0xFF }.ToBase64());
        }

        [Fact]
        public void ByteArray_ToUrlSafeBase64_returns_urlsafe_base64_with_padding()
        {
            Assert.Equal("", new byte[] { }.ToUrlSafeBase64());
            Assert.Equal("-w==", new byte[] { 0xFB }.ToUrlSafeBase64());
            Assert.Equal("--8=", new byte[] { 0xFB, 0xEF }.ToUrlSafeBase64());
            Assert.Equal("--__", new byte[] { 0xFB, 0xEF, 0xFF }.ToUrlSafeBase64());
        }

        [Fact]
        public void ByteArray_ToUrlSafeBase64NoPadding_returns_urlsafe_base64_without_padding()
        {
            Assert.Equal("", new byte[] { }.ToUrlSafeBase64NoPadding());
            Assert.Equal("-w", new byte[] { 0xFB }.ToUrlSafeBase64NoPadding());
            Assert.Equal("--8", new byte[] { 0xFB, 0xEF }.ToUrlSafeBase64NoPadding());
            Assert.Equal("--__", new byte[] { 0xFB, 0xEF, 0xFF }.ToUrlSafeBase64NoPadding());
        }

        [Fact]
        public void ByteArray_ToBigInt_returns_BigInteger()
        {
            Assert.Equal(BigInteger.Zero, new byte[] { }.ToBigInt());
            Assert.Equal(BigInteger.Zero, new byte[] { 0 }.ToBigInt());
            Assert.Equal(new BigInteger(255), new byte[] { 0xFF }.ToBigInt());
            Assert.Equal(new BigInteger(0xDEADBEEF), new byte[] { 0xDE, 0xAD, 0xBE, 0xEF }.ToBigInt());
        }

        //
        // BigInteger
        //

        [Fact]
        public void BigInteger_ToHex_returns_hex_string()
        {
            var testCases = new Dictionary<int, string>
            {
                {0, "0"},
                {1, "1"},
                {0xD, "d"},
                {0xDE, "de"},
                {0xDEA, "dea"},
                {0xDEAD, "dead"},
                {0x80, "80"},
                {0xFF, "ff"},
                {-1, "-1"},
                {-0xD, "-d"},
                {-0xDE, "-de"},
                {-0xDEA, "-dea"},
                {-0xDEAD, "-dead"},
                {-0x80, "-80"},
                {-0xFF, "-ff"},
            };

            foreach (var i in testCases)
                Assert.Equal(i.Value, new BigInteger(i.Key).ToHex());
        }

        [Fact]
        public void BigInteger_ModExp_returns_positive_result()
        {
            var testCases = new[]
            {
                new []{-3, 3, 10, 3},
                new []{-4, 3, 100, 36},
                new []{-4, 3, 1000, 936},
                new []{-1337, 19, 1000000, 594327},
            };

            foreach (var i in testCases)
            {
                var r = new BigInteger(i[0]).ModExp(new BigInteger(i[1]), new BigInteger(i[2]));
                Assert.Equal(new BigInteger(i[3]), r);
            }
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
