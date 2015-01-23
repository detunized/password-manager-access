// Copyright (C) 2015 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace PasswordBox.Test
{
    [TestFixture]
    class CryptoTest
    {
        private const string KeyHex = "bc0d63541710541e493d1077e49e92523a4b7c53af1883266ed6c5be2f1b9562";
        private static readonly byte[] Key = KeyHex.DecodeHex();

        [Test]
        public void Decrypt_returns_correct_result()
        {
            // TODO: Add real data
            var decrypted = Crypto.Decrypt("", KeyHex);
            Assert.IsEmpty(decrypted);
        }

        [Test]
        public void Decrypt_returns_empty_on_empty_base64_input()
        {
            var decrypted = Crypto.Decrypt("", KeyHex);
            Assert.IsEmpty(decrypted);
        }

        [Test]
        public void Decrypt_returns_empty_on_empty_binary_input()
        {
            var decrypted = Crypto.Decrypt("".ToBytes(), Key);
            Assert.IsEmpty(decrypted);
        }

        [Test]
        [ExpectedException(typeof(Exception),
                           ExpectedMessage = "Cipher text is too short (version byte is missing)")]
        public void Decrypt_throws_on_missing_format_byte()
        {
            Crypto.Decrypt("00".DecodeHex(), Key);
        }

        [Test]
        [ExpectedException(typeof(Exception),
                           ExpectedMessage = "Cipher text is too short (IV is missing)")]
        public void Decrypt_throws_on_missing_iv()
        {
            Crypto.Decrypt("0004".DecodeHex(), Key);
        }

        [Test]
        [ExpectedException(typeof(Exception),
                           ExpectedMessage = "Unsupported cipher format version (5)")]
        public void Decrypt_throws_on_unsupported_version()
        {
            Crypto.Decrypt("0005".DecodeHex(), Key);
        }
    }
}
