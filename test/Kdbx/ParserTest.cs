// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using System.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Kdbx;
using Xunit;

namespace PasswordManagerAccess.Test.Kdbx
{
    public class ParserTest: TestBase
    {
        [Theory]
        [InlineData("kdbx4-aes-aes")]
        [InlineData("kdbx4-aes-chacha20")]
        [InlineData("kdbx4-aes-twofish")]
        [InlineData("kdbx4-argon2-aes-1k-block")]
        public void Parse_returns_accounts(string fixture)
        {
            using var db = GetBinaryFixtureStream(fixture, "kdbx");
            var accounts = Parser.Parse(db, "password");

            Assert.NotEmpty(accounts);
        }

        [Theory]
        [InlineData("keyfile-generic", "bin")]
        [InlineData("keyfile-xml", "xml")]
        [InlineData("keyfile-legacy-binary", "bin")]
        [InlineData("keyfile-legacy-hex", "txt")]
        public void Parse_with_keyfile_returns_accounts(string keyfileName, string keyfileExtension)
        {
            using var db = GetBinaryFixtureStream("kdbx4-with-keyfile", "kdbx");
            using var keyfile = GetBinaryFixtureStream(keyfileName, keyfileExtension);
            var accounts = Parser.Parse(db, "password", keyfile);

            Assert.NotEmpty(accounts);
        }

        [Fact]
        public void Parse_returns_accounts_with_fields()
        {
            using var db = GetBinaryFixtureStream("kdbx4-with-fields", "kdbx");
            var accounts = Parser.Parse(db, "password");

            var sorted = accounts.OrderBy(x => x.Name).ToArray();
            Assert.Equal(4, sorted.Length);

            void AssertAccountWithFields(int accountIndex, string accountName, int fieldCount, string fieldValues)
            {
                var account = sorted[accountIndex];
                Assert.Equal(accountName, account.Name);
                Assert.Equal(fieldCount, account.Fields.Count);
                Assert.Equal(fieldValues, account.Fields.Select(x => $"{x.Key}={x.Value}").JoinToString(","));
            }

            AssertAccountWithFields(0, "00 - With 0 fields", 0, "");
            AssertAccountWithFields(1, "01 - With 3 fields", 3, "key1=value1,key2=value2,key3=value3");
            AssertAccountWithFields(2, "02 - With 3 protected fields", 3, "key1=value1,key2=value2,key3=value3");
            AssertAccountWithFields(3,
                                    "03 - With 3 regular and 3 protected fields",
                                    6,
                                    "key1=value1,key2=value2,key3=value3,key4=value4,key5=value5,key6=value6");
        }

        [Fact]
        public void Parse_returns_accounts_with_nested_folders()
        {
            using var db = GetBinaryFixtureStream("kdbx4-with-nested-folders", "kdbx");
            var accounts = Parser.Parse(db, "password");

            var sorted = accounts.OrderBy(x => x.Name).ToArray();
            Assert.Equal(4, sorted.Length);

            void AssertAccountWithFields(int accountIndex, string accountName, string path)
            {
                var account = sorted[accountIndex];
                Assert.Equal(accountName, account.Name);
                Assert.Equal(path, account.Path);
            }

            AssertAccountWithFields(0, "entry0", "level0");
            AssertAccountWithFields(1, "entry1", "level0/level1");
            AssertAccountWithFields(2, "entry2", "level0/level1/level2");
            AssertAccountWithFields(3, "entry3", "level0/level1/level2/level3");
        }

        [Theory]
        [InlineData("keyfile-generic", "bin")]
        [InlineData("keyfile-xml", "xml")]
        [InlineData("keyfile-legacy-binary", "bin")]
        [InlineData("keyfile-legacy-hex", "txt")]
        public void ReadKeyfile_returns_keyfile_content(string keyfileName, string keyfileExtension)
        {
            using var stream = GetBinaryFixtureStream(keyfileName, keyfileExtension);
            var keyfile = Parser.ReadKeyfile(stream);

            Assert.Equal("Id8ZmY3yOAMpIGxfUpjSCnxYx3IcWsp3Ah73r9DFFj4=".Decode64(), keyfile);
        }

        [Theory]
        [InlineData("kdbx4-aes-aes")]
        [InlineData("kdbx4-argon2-aes")]
        [InlineData("kdbx4-aes-chacha20")]
        [InlineData("kdbx4-aes-twofish")]
        public void ParseHeader_works(string fixture)
        {
            var blob = GetBinaryFixture(fixture, "kdbx");
            Parser.ParseHeader(blob, Util.ComposeMasterKey("password", Array.Empty<byte>()));
        }

        [Theory]
        [InlineData("kdbx4-aes-aes", Parser.Cipher.Aes)]
        [InlineData("kdbx4-aes-chacha20", Parser.Cipher.ChaCha20)]
        [InlineData("kdbx4-aes-twofish", Parser.Cipher.Twofish)]
        internal void ReadEncryptionInfo_returns_encryption_info(string fixture, Parser.Cipher cipher)
        {
            var blob = GetBinaryFixture(fixture, "kdbx");
            var io = blob.AsRoSpan().ToStream();
            io.Skip(12); // Skip header
            var info = Parser.ReadEncryptionInfo(ref io);

            Assert.True(info.IsCompressed);
            Assert.Equal(cipher, info.Cipher);
        }

        //
        // Helpers
        //

        private MemoryStream GetBinaryFixtureStream(string name, string extension)
        {
            return new MemoryStream(GetBinaryFixture(name, extension), writable: false);
        }
    }
}
