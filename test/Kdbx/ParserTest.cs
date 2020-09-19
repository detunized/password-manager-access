// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.Kdbx;
using Xunit;

namespace PasswordManagerAccess.Test.Kdbx
{
    public class ParserTest: TestBase
    {
        [Theory]
        [InlineData("kdbx4-aes-aes")]
        [InlineData("kdbx4-argon2-aes")]
        [InlineData("kdbx4-aes-chacha20")]
        [InlineData("kdbx4-aes-twofish")]
        public void ParseHeader_works(string fixture)
        {
            var blob = GetBinaryFixture(fixture, "kdbx");
            Parser.ParseHeader(blob, "password");
        }

        [Theory]
        [InlineData("kdbx4-aes-aes", Parser.Cipher.Aes)]
        [InlineData("kdbx4-aes-chacha20", Parser.Cipher.ChaCha20)]
        [InlineData("kdbx4-aes-twofish", Parser.Cipher.TwoFish)]
        internal void ReadEncryptionInfo_returns_encryption_info(string fixture, Parser.Cipher cipher)
        {
            var blob = GetBinaryFixture(fixture, "kdbx");
            var io = blob.AsRoSpan().ToStream();
            io.Skip(12); // Skip header
            var info = Parser.ReadEncryptionInfo(ref io);

            Assert.True(info.IsCompressed);
            Assert.Equal(cipher, info.Cipher);
        }
    }
}
