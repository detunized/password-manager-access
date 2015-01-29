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
        private const string CiphertextBase64 = "AATXkbQnk41DJzqyfcFtcTaYE+ptuHwtC9TCmVdsK8/uXA==";
        private static readonly byte[] Plaintext = "password".ToBytes();
        private static readonly byte[] Key = KeyHex.DecodeHex();

        [Test]
        public void Decrypt_strings_returns_correct_result()
        {
            var decrypted = Crypto.Decrypt(KeyHex, CiphertextBase64);
            Assert.AreEqual(Plaintext, decrypted);
        }

        [Test]
        public void Decrypt_binary_returns_correct_result()
        {
            var decrypted = Crypto.Decrypt(Key, CiphertextBase64.Decode64());
            Assert.AreEqual(Plaintext, decrypted);
        }

        [Test]
        public void Decrypt_returns_empty_on_empty_base64_input()
        {
            var decrypted = Crypto.Decrypt(KeyHex, "");
            Assert.IsEmpty(decrypted);
        }

        [Test]
        public void Decrypt_returns_empty_on_empty_binary_input()
        {
            var decrypted = Crypto.Decrypt(Key, "".ToBytes());
            Assert.IsEmpty(decrypted);
        }

        [Test]
        [ExpectedException(typeof(Exception),
                           ExpectedMessage = "Ciphertext is too short (version byte is missing)")]
        public void Decrypt_throws_on_missing_format_byte()
        {
            Crypto.Decrypt(Key, "00".DecodeHex());
        }

        [Test]
        [ExpectedException(typeof(Exception),
                           ExpectedMessage = "Ciphertext is too short (IV is missing)")]
        public void Decrypt_throws_on_missing_iv()
        {
            Crypto.Decrypt(Key, "0004".DecodeHex());
        }

        [Test]
        [ExpectedException(typeof(Exception),
                           ExpectedMessage = "Unsupported cipher format version (5)")]
        public void Decrypt_throws_on_unsupported_version()
        {
            Crypto.Decrypt(Key, "0005".DecodeHex());
        }
    }
}
