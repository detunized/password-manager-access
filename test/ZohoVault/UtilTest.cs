// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Common;
using Xunit;
using Util = PasswordManagerAccess.ZohoVault.Util;

namespace PasswordManagerAccess.Test.ZohoVault
{
    public class UtilTest
    {
        // From http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
        public readonly byte[] NistKey = "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4".DecodeHex();
        public readonly byte[] NistCtr = "f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff".DecodeHex();
        public readonly byte[] NistCiphertext = ("601ec313775789a5b7a7f504bbf3d228" +
                                                 "f443e3ca4d62b59aca84e990cacaf5c5" +
                                                 "2b0930daa23de94ce87017ba2d84988d" +
                                                 "dfc9c58db67aada613c2dd08457941a6").DecodeHex();
        public readonly byte[] NistPlaintext = ("6bc1bee22e409f96e93d7e117393172a" +
                                                "ae2d8a571e03ac9c9eb76fac45af8e51" +
                                                "30c81c46a35ce411e5fbc1191a0a52ef" +
                                                "f69f2445df4f9b17ad2b417be66c3710").DecodeHex();

        [Fact]
        public void ComputeKey_returns_key()
        {
            var key = Util.ComputeKey(
                TestData.Passphrase,
                "f78e6ffce8e57501a02c9be303db2c68".ToBytes(),
                1000);
            Assert.Equal(TestData.Key, key);
        }

        [Fact]
        public void Decrypt_returns_plaintext()
        {
            // Calculated with the original Js code
            var plaintext = Util.Decrypt(
                "awNZM8agxVecKpRoC821Oq6NlvVwm6KpPGW+cLdzRoc2Mg5vqPQzoONwww==".Decode64(),
                TestData.Key).ToUtf8();
            Assert.Equal("{\"date\":\"2016-08-30T15:05:42.874Z\"}", plaintext);
        }


        [Fact]
        public void ComputeAesCtrKey_returns_key()
        {
            // Calculated with the original Js code
            var ctrKey = "1fad494b86d62e89f945e8cfb9925e341fad494b86d62e89f945e8cfb9925e34".DecodeHex();
            Assert.Equal(ctrKey, Util.ComputeAesCtrKey(TestData.Key));
        }

        //
        // AES-256 CTR
        //

        [Fact]
        public void DecryptAes256Ctr_decrypts_one_block()
        {
            var ciphertext = NistCiphertext.Take(16).ToArray();
            var plaintext = NistPlaintext.Take(16).ToArray();

            Assert.Equal(plaintext, Util.DecryptAes256Ctr(ciphertext, NistKey, NistCtr));
        }

        [Fact]
        public void DecryptAes256Ctr_decrypts_multiple_blocks()
        {
            Assert.Equal(NistPlaintext, Util.DecryptAes256Ctr(NistCiphertext, NistKey, NistCtr));
        }

        [Fact]
        public void DecryptAes256Ctr_decrypts_empty_input()
        {
            Assert.Equal(new byte[0], Util.DecryptAes256Ctr(new byte[0], NistKey, NistCtr));
        }

        [Fact]
        public void DecryptAes256Ctr_decrypts_unaligned_input()
        {
            for (var i = 1; i < NistCiphertext.Length - 1; i += 1)
            {
                var ciphertext = NistCiphertext.Take(i).ToArray();
                var plaintext = NistPlaintext.Take(i).ToArray();

                Assert.Equal(plaintext, Util.DecryptAes256Ctr(ciphertext, NistKey, NistCtr));
            }
        }

        [Fact]
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
                Util.IncrementCounter(counter);
                Assert.Equal(i.Value.DecodeHex(), counter);
            }
        }
    }
}
