// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.OpVault;
using Xunit;

namespace PasswordManagerAccess.Test.OpVault
{
    public class ExtensionsTest
    {
        //
        // string
        //

        [Fact]
        public void String_ToBytes_converts_string_to_utf8_bytes()
        {
            Assert.Equal(new byte[]{}, "".ToBytes());
            Assert.Equal(TestBytes, TestString.ToBytes());
        }

        [Fact]
        public void String_String_Decode64_decodes_base64()
        {
            Assert.Equal(new byte[]{}, "".Decode64());
            Assert.Equal(new byte[]{0x61}, "YQ==".Decode64());
            Assert.Equal(new byte[]{0x61, 0x62}, "YWI=".Decode64());
            Assert.Equal(new byte[]{0x61, 0x62, 0x63}, "YWJj".Decode64());
            Assert.Equal(new byte[]{0x61, 0x62, 0x63, 0x64}, "YWJjZA==".Decode64());
        }

        //
        // byte[]
        //

        [Fact]
        public void ByteArray_ToUtf8_returns_string()
        {
            Assert.Equal("", new byte[]{}.ToUtf8());
            Assert.Equal(TestString, TestBytes.ToUtf8());
        }

        //
        // JToken
        //

        [Fact]
        public void JToken_chained_At_returns_token()
        {
            var j = JObject.Parse(@"{
                'k1': {'k2': {'k3': 'v3'}}
            }");

            var k1 = j["k1"];
            var k2 = j["k1"]["k2"];
            var k3 = j["k1"]["k2"]["k3"];

            Assert.Equal(k1, j.At("k1"));
            Assert.Equal(k2, j.At("k1").At("k2"));
            Assert.Equal(k3, j.At("k1").At("k2").At("k3"));

            Assert.Equal(k3, j.At("k1").At("k2/k3"));
            Assert.Equal(k3, j.At("k1/k2").At("k3"));
        }

        [Fact]
        public void JToken_At_throws_on_invalid_path()
        {
            var j = JObject.Parse(@"{
                'k1': 'v1',
                'k2': {'k22': 'v22'},
                'k3': {'k33': {'k333': 'v333'}}
            }");

            VerifyAtThrows(j, "i1");
            VerifyAtThrows(j, "k1/k11");
            VerifyAtThrows(j, "k2/i2");
            VerifyAtThrows(j, "k2/k22/i22");
            VerifyAtThrows(j, "k3/i3");
            VerifyAtThrows(j, "k3/k33/i33");
            VerifyAtThrows(j, "k3/k33/k333/i333");
        }

        [Fact]
        public void JToken_At_throws_on_non_objects()
        {
            var j = JObject.Parse(@"{
                'k1': [],
                'k2': true,
                'k3': 10
            }");

            VerifyAtThrows(j, "k1/0");
            VerifyAtThrows(j, "k2/k22");
            VerifyAtThrows(j, "k3/k33/k333");
        }

        [Fact]
        public void JToken_At_returns_default_value_on_invalid_path()
        {
            var j = JObject.Parse(@"{
                'k1': 'v1',
                'k2': {'k22': 'v22'},
                'k3': {'k33': {'k333': 'v333'}}
            }");

            VerifyAtReturnsDefault(j, "i1");
            VerifyAtReturnsDefault(j, "k1/k11");
            VerifyAtReturnsDefault(j, "k2/i2");
            VerifyAtReturnsDefault(j, "k2/k22/i22");
            VerifyAtReturnsDefault(j, "k3/i3");
            VerifyAtReturnsDefault(j, "k3/k33/i33");
            VerifyAtReturnsDefault(j, "k3/k33/k333/i333");
        }

        [Fact]
        public void JToken_StringAt_returns_string()
        {
            var j = JObject.Parse(@"{
                'k1': 'v1',
                'k2': {'k22': 'v22'},
                'k3': {'k33': {'k333': 'v333'}}
            }");

            Assert.Equal("v1", j.StringAt("k1"));
            Assert.Equal("v22", j.StringAt("k2/k22"));
            Assert.Equal("v333", j.StringAt("k3/k33/k333"));
        }

        [Fact]
        public void JToken_StringAt_throws_on_non_stings()
        {
            var j = JObject.Parse(@"{
                'k1': true,
                'k2': 10,
                'k3': 10.0,
                'k4': [],
                'k5': {},
            }");

            VerifyStringAtThrows(j, "k1");
            VerifyStringAtThrows(j, "k2");
            VerifyStringAtThrows(j, "k3");
            VerifyStringAtThrows(j, "k4");
            VerifyStringAtThrows(j, "k5");
        }

        [Fact]
        public void JToken_StringAt_returns_default_value_on_non_strings()
        {
            var j = JObject.Parse(@"{
                'k1': true,
                'k2': 10,
                'k3': 10.0,
                'k4': [],
                'k5': {},
            }");

            VerifyStringAtReturnsDefault(j, "k1");
            VerifyStringAtReturnsDefault(j, "k2");
            VerifyStringAtReturnsDefault(j, "k3");
            VerifyStringAtReturnsDefault(j, "k4");
            VerifyStringAtReturnsDefault(j, "k5");
        }

        [Fact]
        public void JToken_IntAt_returns_int()
        {
            var j = JObject.Parse(@"{
                'k1': 13,
                'k2': {'k22': 42},
                'k3': {'k33': {'k333': 1337}}
            }");

            Assert.Equal(13, j.IntAt("k1"));
            Assert.Equal(42, j.IntAt("k2/k22"));
            Assert.Equal(1337, j.IntAt("k3/k33/k333"));
        }

        [Fact]
        public void JToken_IntAt_throws_on_non_ints()
        {
            var j = JObject.Parse(@"{
                'k1': true,
                'k2': '10',
                'k3': 10.0,
                'k4': [],
                'k5': {},
            }");

            VerifyIntAtThrows(j, "k1");
            VerifyIntAtThrows(j, "k2");
            VerifyIntAtThrows(j, "k3");
            VerifyIntAtThrows(j, "k4");
            VerifyIntAtThrows(j, "k5");
        }

        [Fact]
        public void JToken_IntAtOrNull_returns_default_value_on_non_ints()
        {
            var j = JObject.Parse(@"{
                'k1': true,
                'k2': '10',
                'k3': 10.0,
                'k4': [],
                'k5': {},
            }");

            VerifyIntAtReturnsDefault(j, "k1");
            VerifyIntAtReturnsDefault(j, "k2");
            VerifyIntAtReturnsDefault(j, "k3");
            VerifyIntAtReturnsDefault(j, "k4");
            VerifyIntAtReturnsDefault(j, "k5");
        }

        [Fact]
        public void JToken_BoolAt_returns_bools()
        {
            var j = JObject.Parse(@"{
                'k1': true,
                'k2': {'k22': false},
                'k3': {'k33': {'k333': true}}
            }");

            Assert.True(j.BoolAt("k1"));
            Assert.False(j.BoolAt("k2/k22"));
            Assert.True(j.BoolAt("k3/k33/k333"));
        }

        [Fact]
        public void JToken_BoolAt_throws_on_non_bools()
        {
            var j = JObject.Parse(@"{
                'k1': 10,
                'k2': '10',
                'k3': 10.0,
                'k4': [],
                'k5': {},
            }");

            VerifyBoolAtThrows(j, "k1");
            VerifyBoolAtThrows(j, "k2");
            VerifyBoolAtThrows(j, "k3");
            VerifyBoolAtThrows(j, "k4");
            VerifyBoolAtThrows(j, "k5");
        }

        [Fact]
        public void JToken_BoolAtOrNull_returns_null_on_non_bools()
        {
            var j = JObject.Parse(@"{
                'k1': 10,
                'k2': '10',
                'k3': 10.0,
                'k4': [],
                'k5': {},
            }");

            VerifyBoolAtReturnsDefault(j, "k1");
            VerifyBoolAtReturnsDefault(j, "k2");
            VerifyBoolAtReturnsDefault(j, "k3");
            VerifyBoolAtReturnsDefault(j, "k4");
            VerifyBoolAtReturnsDefault(j, "k5");
        }

        //
        // Data
        //

        private const string TestString = "All your base are belong to us";

        private static readonly byte[] TestBytes =
        {
            65, 108, 108, 32, 121, 111, 117, 114, 32, 98, 97, 115, 101, 32, 97,
            114, 101, 32, 98, 101, 108, 111, 110, 103, 32, 116, 111, 32, 117, 115
        };

        //
        // Helpers
        //

        private static void VerifyAtThrows(JToken token, string path)
        {
            VerifyAccessThrows(token, path, (t, p) => t.At(p));
        }

        private static void VerifyStringAtThrows(JToken token, string path)
        {
            VerifyAccessThrows(token, path, (t, p) => t.StringAt(p));
        }

        private static void VerifyIntAtThrows(JToken token, string path)
        {
            VerifyAccessThrows(token, path, (t, p) => t.IntAt(p));
        }

        private static void VerifyBoolAtThrows(JToken token, string path)
        {
            VerifyAccessThrows(token, path, (t, p) => t.BoolAt(p));
        }

        private static void VerifyAccessThrows(JToken token, string path, Action<JToken, string> access)
        {
            Assert.Throws<JTokenAccessException>(() => access(token, path));
        }

        private static void VerifyAtReturnsDefault(JToken token, string path)
        {
            var dv = new JArray();
            Assert.Same(dv, token.At(path, dv));
        }

        private static void VerifyStringAtReturnsDefault(JToken token, string path)
        {
            Assert.Equal("default", token.StringAt(path, "default"));
        }

        private static void VerifyIntAtReturnsDefault(JToken token, string path)
        {
            Assert.Equal(1337, token.IntAt(path, 1337));
        }

        private static void VerifyBoolAtReturnsDefault(JToken token, string path)
        {
            Assert.False(token.BoolAt(path, false));
            Assert.True(token.BoolAt(path, true));
        }
    }
}