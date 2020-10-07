// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
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
