// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class AccountKeyTest
    {
        [Test]
        public void Parse_returns_parsed_format_A3_key()
        {
            var key = AccountKey.Parse(KeyString);

            Assert.That(key.Format, Is.EqualTo("A3"));
            Assert.That(key.Uuid, Is.EqualTo("RTN9SA"));
            Assert.That(key.Key, Is.EqualTo("DY9445Y5FF96X6E7B5GPFA95R9"));
        }

        [Test]
        public void Parse_returns_parsed_format_A2_key()
        {
            // This a made up test. I don't have an existing example of a key in this format.
            var key = AccountKey.Parse("A2-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R");

            Assert.That(key.Format, Is.EqualTo("A2"));
            Assert.That(key.Uuid, Is.EqualTo("RTN9SA"));
            Assert.That(key.Key, Is.EqualTo("DY9445Y5FF96X6E7B5GPFA95R"));
        }

        [Test]
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
                Assert.That(() => AccountKey.Parse(key),
                            ExceptionsTest.ThrowsInvalidOpeationWithMessage("Invalid account key"));
        }

        [Test]
        public void Hash_returnes_hashed_key()
        {
            Assert.That(Key.Hash(),
                        Is.EqualTo("ZlI2kRote1dv7uflTenyIp5jBE0u-7Fl4aIiE0D9L-g".Decode64()));
        }

        [Test]
        public void CombineWith_returnes_hashed_key()
        {
            Assert.That(Key.CombineWith("All your base are belong to us!!".ToBytes()),
                        Is.EqualTo("Jz5asWNCDiVPjIaWKMmTUPtDZihClN8CwdZNMzWODsk".Decode64()));
        }

        [Test]
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
                Assert.That(() => Key.CombineWith(b.ToBytes()),
                            ExceptionsTest.ThrowsInvalidOpeationWithMessage("hash function"));
        }

        //
        // Data
        //

        private const string KeyString = "A3-RTN9SA-DY9445Y5FF96X6E7B5GPFA95R9";
        private static readonly AccountKey Key = new AccountKey("A3",
                                                                "RTN9SA",
                                                                "DY9445Y5FF96X6E7B5GPFA95R9");
    }
}
