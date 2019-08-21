// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Newtonsoft.Json.Linq;
using Xunit;
using PasswordManagerAccess.Dashlane;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class ExtensionsTest
    {
        public const string TestString = "All your base are belong to us";
        public const string TestHex = "416c6c20796f75722062617365206172652062656c6f6e6720746f207573";
        public static readonly byte[] TestBytes = {
            65, 108, 108, 32, 121, 111, 117, 114, 32, 98, 97, 115, 101, 32, 97,
            114, 101, 32, 98, 101, 108, 111, 110, 103, 32, 116, 111, 32, 117, 115
        };

        [Fact]
        public void String_ToBytes_converts_string_to_utf8_bytes()
        {
            Assert.Equal(new byte[]{}, "".ToBytes());
            Assert.Equal(TestBytes, TestString.ToBytes());
        }

        [Fact]
        public void String_Decode64_decodes_base64()
        {
            Assert.Equal(new byte[]{}, "".Decode64());
            Assert.Equal(new byte[]{0x61}, "YQ==".Decode64());
            Assert.Equal(new byte[]{0x61, 0x62}, "YWI=".Decode64());
            Assert.Equal(new byte[]{0x61, 0x62, 0x63}, "YWJj".Decode64());
            Assert.Equal(new byte[]{0x61, 0x62, 0x63, 0x64}, "YWJjZA==".Decode64());
        }

        [Fact]
        public void ByteArray_ToUtf8_returns_string()
        {
            Assert.Equal("", new byte[]{}.ToUtf8());
            Assert.Equal(TestString, TestBytes.ToUtf8());
        }

        [Fact]
        public void ByteArray_ToHex_returns_hex_string()
        {
            Assert.Equal("", new byte[]{}.ToHex());
            Assert.Equal(TestHex, TestBytes.ToHex());
        }

        [Fact]
        public void ByteArray_Sub_returns_subarray()
        {
            var array = "0123456789abcdef".ToBytes();
            var check = new Action<int, int, string>((start, length, expected) =>
                Assert.Equal(expected.ToBytes(), array.Sub(start, length)));

            // Subarrays at 0, no overflow
            check(0, 1, "0");
            check(0, 2, "01");
            check(0, 3, "012");
            check(0, 15, "0123456789abcde");
            check(0, 16, "0123456789abcdef");

            // Subarrays in the middle, no overflow
            check(1, 1, "1");
            check(3, 2, "34");
            check(8, 3, "89a");
            check(15, 1, "f");

            // Subarrays of zero length, no overflow
            check(0, 0, "");
            check(1, 0, "");
            check(9, 0, "");
            check(15, 0, "");

            // Subarrays at 0 with overflow
            check(0, 17, "0123456789abcdef");
            check(0, 12345, "0123456789abcdef");
            check(0, int.MaxValue, "0123456789abcdef");

            // Subarrays in the middle with overflow
            check(1, 16, "123456789abcdef");
            check(1, 12345, "123456789abcdef");
            check(8, 9, "89abcdef");
            check(8, 67890, "89abcdef");
            check(15, 2, "f");
            check(15, int.MaxValue, "f");

            // Subarrays beyond the end
            check(16, 0, "");
            check(16, 1, "");
            check(16, 16, "");
            check(16, int.MaxValue, "");
            check(12345, 0, "");
            check(12345, 1, "");
            check(12345, 56789, "");
            check(12345, int.MaxValue, "");
            check(int.MaxValue, 0, "");
            check(int.MaxValue, 1, "");
            check(int.MaxValue, 12345, "");
            check(int.MaxValue, int.MaxValue, "");
        }

        [Fact]
        public void ByteArray_Sub_throws_on_negative_length()
        {
            var e = Assert.Throws<ArgumentOutOfRangeException>(() => new byte[] {}.Sub(0, -1337));
            Assert.Equal("Length should be nonnegative\r\nParameter name: length", e.Message);
        }

        [Fact]
        public void JToken_GetString_returns_string()
        {
            Action<string, string> check = (json, key) => 
                Assert.Equal("value", JToken.Parse(json).GetString(key));

            check("{'key': 'value'}", "key");
            check("{'key': {'kee': 'value'}}", "key.kee");
        }

        [Fact]
        public void JToken_GetString_returns_null()
        {
            Action<string, string> check = (json, key) => Assert.Null(JToken.Parse(json).GetString(key));

            check("0", "key");
            check("''", "key");
            check("[]", "key");
            check("{}", "key");
            check("{'key': 0}", "key");
            check("{'key': []}", "key");
            check("{'key': {}}", "key");
            check("{'key': 'value'}", "kee");
        }
    }
}
