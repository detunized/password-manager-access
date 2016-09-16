// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using NUnit.Framework;

namespace ZohoVault.Test
{
    [TestFixture]
    class CryptoTest
    {
        // Calculated with the original Js code
        public readonly byte[] Key = "d7643007973dba7243d724f66fd806bf".ToBytes();

        [Test]
        public void ComputeAesCtrKey_returns_key()
        {
            // Calculated with the original Js code
            var ctrKey = "1fad494b86d62e89f945e8cfb9925e341fad494b86d62e89f945e8cfb9925e34".DecodeHex();
            Assert.That(Crypto.ComputeAesCtrKey(Key), Is.EqualTo(ctrKey));
        }

        [Test]
        public void DecryptAes256Ctr_returns_plaintext()
        {
            // From http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
            var key = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".DecodeHex();
            var ctr = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".DecodeHex();
            var ciphertext = "601ec313775789a5b7a7f504bbf3d228".DecodeHex();
            var plaintext = "6bc1bee22e409f96e93d7e117393172a".DecodeHex();

            Assert.That(Crypto.DecryptAes256Ctr(ciphertext, key, ctr), Is.EqualTo(plaintext));
        }

        [Test]
        public void IncrementCounter_adds_one()
        {
            var testCases = new Dictionary<string, string>
            {
                {"", ""},
                {"00", "01"},
                {"7f", "80"},
                {"fe", "ff"},
                {"ff", "00"},
                {"000000", "000001"},
                {"0000ff", "000100"},
                {"00ffff", "010000"},
                {"ffffff", "000000"},
                {"abcdefffffffffffffffffff", "abcdf0000000000000000000"},
                {"ffffffffffffffffffffffff", "000000000000000000000000"},
            };

            foreach (var i in testCases)
            {
                var counter = i.Key.DecodeHex();
                Crypto.IncrementCounter(counter);
                Assert.That(counter, Is.EqualTo(i.Value.DecodeHex()));
            }
        }
    }
}
