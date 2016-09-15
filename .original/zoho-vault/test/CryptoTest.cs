// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace ZohoVault.Test
{
    [TestFixture]
    class CryptoTest
    {
        public readonly byte[] Key = "d7643007973dba7243d724f66fd806bf".ToBytes();

        [Test]
        public void ComputeAesCtrKey_returns_key()
        {
            Assert.That(
                Crypto.ComputeAesCtrKey(Key).ToHex(),
                Is.EqualTo("1fad494b86d62e89f945e8cfb9925e341fad494b86d62e89f945e8cfb9925e34"));
        }

        [Test]
        public void DecryptAes256Ctr_returns_plaintext()
        {
            // From http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
            var key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4";
            var ctr = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff";
            var ciphertext = "601ec313775789a5b7a7f504bbf3d228";
            var plaintext = "6bc1bee22e409f96e93d7e117393172a";

            Assert.That(
                Crypto.DecryptAes256Ctr(StringToByteArray(ciphertext), StringToByteArray(key), StringToByteArray(ctr)).ToHex(),
                Is.EqualTo(plaintext));
        }

        //
        // Helpers
        //

        // TODO: Move to extensions
        public static byte[] StringToByteArray(String hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }
    }
}
