// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class AccountKeyTest
    {
        [Fact]
        public void Parse_returns_parsed_format_A3_key()
        {
            var key = AccountKey.Parse(KeyString);

            Assert.Equal("A3", key.Format);
            Assert.Equal("RTN9SA", key.Uuid);
            Assert.Equal("DY9445Y5FF96X6E7B5GPFA95R9", key.Key);
        }

        [Fact]
        public void Parse_returns_parsed_format_A2_key()
        {
            // This a made up test. I don't have an existing example of a key in this format.
            var key = AccountKey.Parse("A2-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R");

            Assert.Equal("A2", key.Format);
            Assert.Equal("RTN9SA", key.Uuid);
            Assert.Equal("DY9445Y5FF96X6E7B5GPFA95R", key.Key);
        }

        [Fact]
        public void Parse_throws_on_invalid_key_format()
        {
            var keys = new[]
            {
                "", // Too short for format
                "A", // Too short for format
                "A2", // Too short
                "A3", // Too short
                "A2-RTN9SA-DY9445Y5FF96X6E7B5GPFA95", // Too short for A2
                "A2-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9", // Too long for A2
                "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R", // Too short for A3
                "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R99", // Too long for A3
                "A3-RTN9SA-DY9445Y-FF96X6E7B-GPFA95R9" // Too short for A3 after removing of "-"
            };

            foreach (var key in keys)
            {
                var e = Assert.Throws<InvalidOperationException>(() => AccountKey.Parse(key));
                Assert.Contains("Invalid account key", e.Message);
            }
        }

        [Fact]
        public void Hash_returnes_hashed_key()
        {
            Assert.Equal("ZlI2kRote1dv7uflTenyIp5jBE0u-7Fl4aIiE0D9L-g".Decode64Loose(), Key.Hash());
        }

        [Fact]
        public void CombineWith_returnes_hashed_key()
        {
            Assert.Equal("Jz5asWNCDiVPjIaWKMmTUPtDZihClN8CwdZNMzWODsk".Decode64Loose(),
                         Key.CombineWith("All your base are belong to us!!".ToBytes()));
        }

        [Fact]
        public void CombineWith_throws_on_incorrect_length()
        {
            var bytes = new[]
            {
                "",
                "A",
                "All your base are belong to us",
                "All your base are belong to us!",
                "All your base are belong to us!!!",
            };

            foreach (var b in bytes)
            {
                var e = Assert.Throws<InvalidOperationException>(() => Key.CombineWith(b.ToBytes()));
                Assert.Contains("hash function", e.Message);
            }
        }

        //
        // Data
        //

        private const string KeyString = "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9";
        private static readonly AccountKey Key = new AccountKey("A3", "RTN9SA", "DY9445Y5FF96X6E7B5GPFA95R9");
    }
}
