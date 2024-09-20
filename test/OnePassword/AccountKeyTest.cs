// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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

        [Theory]
        [InlineData("")] // Too short for format
        [InlineData("A")] // Too short for format
        [InlineData("A2")] // Too short
        [InlineData("A3")] // Too short
        [InlineData("A2-RTN9SA-DY9445Y5FF96X6E7B5GPFA95")] // Too short for A2
        [InlineData("A2-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9")] // Too long for A2
        [InlineData("A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R")] // Too short for A3
        [InlineData("A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R99")] // Too long for A3
        [InlineData("A3-RTN9SA-DY9445Y-FF96X6E7B-GPFA95R9")] // Too short for A3 after removing of "-"
        public void Parse_throws_on_invalid_key_format(string key)
        {
            Exceptions.AssertThrowsInternalError(() => AccountKey.Parse(key), "Invalid account key");
        }

        [Fact]
        public void Hash_returnes_hashed_key()
        {
            Assert.Equal("ZlI2kRote1dv7uflTenyIp5jBE0u-7Fl4aIiE0D9L-g".Decode64Loose(), Key.Hash());
        }

        [Fact]
        public void CombineWith_returnes_hashed_key()
        {
            Assert.Equal(
                "Jz5asWNCDiVPjIaWKMmTUPtDZihClN8CwdZNMzWODsk".Decode64Loose(),
                Key.CombineWith("All your base are belong to us!!".ToBytes())
            );
        }

        [Theory]
        [InlineData("")]
        [InlineData("A")]
        [InlineData("All your base are belong to us")]
        [InlineData("All your base are belong to us!")]
        [InlineData("All your base are belong to us!!!")]
        public void CombineWith_throws_on_incorrect_length(string bytes)
        {
            Exceptions.AssertThrowsInternalError(() => Key.CombineWith(bytes.ToBytes()), "hash function");
        }

        //
        // Data
        //

        private const string KeyString = "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9";
        private static readonly AccountKey Key = new AccountKey("A3", "RTN9SA", "DY9445Y5FF96X6E7B5GPFA95R9");
    }
}
