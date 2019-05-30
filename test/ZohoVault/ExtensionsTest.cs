// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.ZohoVault;
using Xunit;

namespace PasswordManagerAccess.Test.ZohoVault
{
    public class ExtensionsTest
    {
        public const string TestString = "All your base are belong to us";
        public const string TestHex = "416c6c20796f75722062617365206172652062656c6f6e6720746f207573";
        public static readonly byte[] TestBytes = {
            65, 108, 108, 32, 121, 111, 117, 114, 32, 98, 97, 115, 101, 32, 97,
            114, 101, 32, 98, 101, 108, 111, 110, 103, 32, 116, 111, 32, 117, 115
        };
        public readonly Dictionary<string, byte[]> HexToBytes = new Dictionary<string, byte[]> {
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

        //
        // JToken
        //

        // TODO: Test *OrNull methods

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
            Assert.Throws<ArgumentException>(() => j.At("i1"));
            Assert.Throws<ArgumentException>(() => j.At("k1/k11"));

            Assert.Throws<ArgumentException>(() => j.At("k2/i2"));
            Assert.Throws<ArgumentException>(() => j.At("k2/k22/i22"));

            Assert.Throws<ArgumentException>(() => j.At("k3/i3"));
            Assert.Throws<ArgumentException>(() => j.At("k3/k33/i33"));
            Assert.Throws<ArgumentException>(() => j.At("k3/k33/k333/i333"));
        }

        [Fact]
        public void JToken_At_throws_on_non_objects()
        {
            var j = JObject.Parse(@"{
                'k1': [],
                'k2': true,
                'k3': 10
            }");
            Assert.Throws<ArgumentException>(() => j.At("k1/0"));
            Assert.Throws<ArgumentException>(() => j.At("k2/k22"));
            Assert.Throws<ArgumentException>(() => j.At("k3/k33/k333"));
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
            Assert.Throws<ArgumentException>(() => j.StringAt("k1"));
            Assert.Throws<ArgumentException>(() => j.StringAt("k2"));
            Assert.Throws<ArgumentException>(() => j.StringAt("k3"));
            Assert.Throws<ArgumentException>(() => j.StringAt("k4"));
            Assert.Throws<ArgumentException>(() => j.StringAt("k5"));
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
            Assert.Throws<ArgumentException>(() => j.IntAt("k1"));
            Assert.Throws<ArgumentException>(() => j.IntAt("k2"));
            Assert.Throws<ArgumentException>(() => j.IntAt("k3"));
            Assert.Throws<ArgumentException>(() => j.IntAt("k4"));
            Assert.Throws<ArgumentException>(() => j.IntAt("k5"));
        }
    }
}
