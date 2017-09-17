// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class AesGcmTest
    {
        //
        // Encrypt
        //

        [Test]
        public void Encrypt_returns_ciphertext()
        {
            foreach (var i in TestCases)
            {
                var ecnrypted = AesGcm.Encrypt(i.Key, i.Plaintext, i.Iv, i.AuthData);
                Assert.That(ecnrypted, Is.EqualTo(i.CiphertextWithTag));
            }
        }

        [Test]
        public void Encrypt_throws_on_invalid_key_length()
        {
            Assert.That(
                () => AesGcm.Encrypt(key: new byte[13],
                                     plaintext: new byte[16],
                                     iv: new byte[12],
                                     authData: new byte[0]),
                ExceptionsTest.ThrowsInvalidOpeationWithMessage("key must"));
        }

        [Test]
        public void Encrypt_throws_on_invalid_iv_length()
        {
            Assert.That(
                () => AesGcm.Encrypt(key: new byte[32],
                                     plaintext: new byte[16],
                                     iv: new byte[13],
                                     authData: new byte[0]),
                ExceptionsTest.ThrowsInvalidOpeationWithMessage("iv must"));
        }

        //
        // Decrypt
        //

        [Test]
        public void Decrypt_returns_plaintext()
        {
            foreach (var i in TestCases)
            {
                var decrypted = AesGcm.Decrypt(i.Key, i.CiphertextWithTag, i.Iv, i.AuthData);
                Assert.That(decrypted, Is.EqualTo(i.Plaintext));
            }
        }

        [Test]
        public void Decrypt_throws_on_invalid_key_length()
        {
            Assert.That(
                () => AesGcm.Decrypt(key: new byte[13],
                                     ciphertext: new byte[16],
                                     iv: new byte[12],
                                     authData: new byte[0]),
                ExceptionsTest.ThrowsInvalidOpeationWithMessage("key must"));
        }

        [Test]
        public void Decrypt_throws_on_invalid_ciphertext_length()
        {
            Assert.That(
                () => AesGcm.Decrypt(key: new byte[32],
                                     ciphertext: new byte[13],
                                     iv: new byte[12],
                                     authData: new byte[0]),
                ExceptionsTest.ThrowsInvalidOpeationWithMessage("ciphertext must"));
        }

        [Test]
        public void Decrypt_throws_on_invalid_iv_length()
        {
            Assert.That(
                () => AesGcm.Decrypt(key: new byte[32],
                                     ciphertext: new byte[16],
                                     iv: new byte[13],
                                     authData: new byte[0]),
                ExceptionsTest.ThrowsInvalidOpeationWithMessage("iv must"));
        }

        [Test]
        public void Decrypt_throws_on_modified_ciphertext()
        {
            foreach (var i in TestCases)
            {
                // Change the first byte of the ciphertext
                var modified = Modified(i.CiphertextWithTag, 0);
                Assert.That(() => AesGcm.Decrypt(i.Key, modified, i.Iv, i.AuthData),
                            ExceptionsTest.ThrowsInvalidOpeationWithMessage("auth tag"));
            }
        }

        [Test]
        public void Decrypt_throws_on_modified_tag()
        {
            foreach (var i in TestCases)
            {
                // Change the last byte in the tag
                var modified = Modified(i.CiphertextWithTag, -1);
                Assert.That(() => AesGcm.Decrypt(i.Key, modified, i.Iv, i.AuthData),
                            ExceptionsTest.ThrowsInvalidOpeationWithMessage("auth tag"));
            }
        }

        //
        // GHash
        //

        [Test]
        public void GHash_returns_hash()
        {
            foreach (var i in TestCases)
            {
                var hash = AesGcm.GHash(i.HashKey,
                                        i.AuthData,
                                        i.AuthData.Length,
                                        i.Ciphertext,
                                        i.Ciphertext.Length);
                Assert.That(hash, Is.EqualTo(i.GHash));
            }
        }

        [Test]
        public void IncrementCounter_overflows_into_next_byte()
        {
            var testCases = new Dictionary<string, string>
            {
                {"000000000000000000000000" + "000000ff", "000000000000000000000000" + "00000100"},
                {"000000000000000000000000" + "0000ffff", "000000000000000000000000" + "00010000"},
                {"000000000000000000000000" + "00ffffff", "000000000000000000000000" + "01000000"},
                {"000000000000000000000000" + "ffffffff", "000000000000000000000000" + "00000000"},
            };

            foreach (var i in testCases)
            {
                var counter = i.Key.DecodeHex();
                AesGcm.IncrementCounter(counter);

                Assert.That(counter, Is.EqualTo(i.Value.DecodeHex()));
            }
        }

        //
        // Data
        //

        private struct TestCase
        {
            public readonly byte[] Key;
            public readonly byte[] Plaintext;
            public readonly byte[] Iv;
            public readonly byte[] AuthData;
            public readonly byte[] Ciphertext;
            public readonly byte[] CiphertextWithTag;

            public readonly byte[] HashKey;
            public readonly byte[] GHash;

            public TestCase(string key,
                            string plaintext,
                            string iv,
                            string authData,
                            string ciphertext,
                            string tag,
                            string hashKey,
                            string gHash)
            {
                Key = key.DecodeHex();
                Plaintext = plaintext.DecodeHex();
                Iv = iv.DecodeHex();
                AuthData = authData.DecodeHex();
                Ciphertext = ciphertext.DecodeHex();
                CiphertextWithTag = (ciphertext + tag).DecodeHex();

                HashKey = hashKey.DecodeHex();
                GHash = gHash.DecodeHex();
            }
        }

        // Test vectors are from
        // http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
        private static readonly TestCase[] TestCases =
        {
            new TestCase(
                key: "e3c08a8f06c6e3ad95a70557b23f75483ce33021a9c72b7025666204c69c0b72",
                plaintext: "",
                iv: "12153524c0895e81b2c28465",
                authData: "d609b1f056637a0d46df998d88e5222ab2c2846512153524c0895e8108000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233340001",
                ciphertext: "",
                tag: "2f0bc5af409e06d609ea8b7d0fa5ea50",
                hashKey: "286d73994ea0ba3cfd1f52bf06a8acf2",
                gHash: "5e4691528f50e5ab5ec346a7bc264a46"),

            new TestCase(
                key: "e3c08a8f06c6e3ad95a70557b23f75483ce33021a9c72b7025666204c69c0b72",
                plaintext: "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a0002",
                iv: "12153524c0895e81b2c28465",
                authData: "d609b1f056637a0d46df998d88e52e00b2c2846512153524c0895e81",
                ciphertext: "e2006eb42f5277022d9b19925bc419d7a592666c925fe2ef718eb4e308efeaa7c5273b394118860a5be2a97f56ab7836",
                tag: "5ca597cdbb3edb8d1a1151ea0af7b436",
                hashKey: "286d73994ea0ba3cfd1f52bf06a8acf2",
                gHash: "2de8c33074f038f04d389c30b9741420"),

            new TestCase(
                key: "691d3ee909d7f54167fd1ca0b5d769081f2bde1aee655fdbab80bd5295ae6be7",
                plaintext: "",
                iv: "f0761e8dcd3d000176d457ed",
                authData: "e20106d7cd0df0761e8dcd3d88e5400076d457ed08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a0003",
                ciphertext: "",
                tag: "35217c774bbc31b63166bcf9d4abed07",
                hashKey: "1e693c484ab894b26669bc12e6d5d776",
                gHash: "b2c0ff13d15fd66dc643d96886687725"),

            new TestCase(
                key: "691d3ee909d7f54167fd1ca0b5d769081f2bde1aee655fdbab80bd5295ae6be7",
                plaintext: "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f30313233340004",
                iv: "f0761e8dcd3d000176d457ed",
                authData: "e20106d7cd0df0761e8dcd3d88e54c2a76d457ed",
                ciphertext: "c1623f55730c93533097addad25664966125352b43adacbd61c5ef3ac90b5bee929ce4630ea79f6ce519",
                tag: "12af39c2d1fdc2051f8b7b3c9d397ef2",
                hashKey: "1e693c484ab894b26669bc12e6d5d776",
                gHash: "954ebaa64b1e25dee8ae1eadcffae4d0"),

            new TestCase(
                key: "83c093b58de7ffe1c0da926ac43fb3609ac1c80fee1b624497ef942e2f79a823",
                plaintext: "",
                iv: "7cfde9f9e33724c68932d612",
                authData: "84c5d513d2aaf6e5bbd2727788e523008932d6127cfde9f9e33724c608000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f0005",
                ciphertext: "",
                tag: "6ee160e8faeca4b36c86b234920ca975",
                hashKey: "d03d3b51fdf2aacb3a165d7dc362d929",
                gHash: "879fc806beb90aca80c497fe514c4a53"),

            new TestCase(
                key: "83c093b58de7ffe1c0da926ac43fb3609ac1c80fee1b624497ef942e2f79a823",
                plaintext: "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b0006",
                iv: "7cfde9f9e33724c68932d612",
                authData: "84c5d513d2aaf6e5bbd2727788e52f008932d6127cfde9f9e33724c6",
                ciphertext: "110222ff8050cbece66a813ad09a73ed7a9a089c106b959389168ed6e8698ea902eb1277dbec2e68e473155a15a7daeed4",
                tag: "a10f4e05139c23df00b3aadc71f0596a",
                hashKey: "d03d3b51fdf2aacb3a165d7dc362d929",
                gHash: "4871e6eb57c98da6ecf18f16b2b0ba4c"),

            new TestCase(
                key: "4c973dbc7364621674f8b5b89e5c15511fced9216490fb1c1a2caa0ffe0407e5",
                plaintext: "",
                iv: "7ae8e2ca4ec500012e58495c",
                authData: "68f2e77696ce7ae8e2ca4ec588e541002e58495c08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d0007",
                ciphertext: "",
                tag: "00bda1b7e87608bcbf470f12157f4c07",
                hashKey: "9a5e559a96459c21e43c0dff0fa426f3",
                gHash: "31d2ff6ce05fa42ecee1a0e58a494cb8"),

            new TestCase(
                key: "4c973dbc7364621674f8b5b89e5c15511fced9216490fb1c1a2caa0ffe0407e5",
                plaintext: "08000f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748490008",
                iv: "7ae8e2ca4ec500012e58495c",
                authData: "68f2e77696ce7ae8e2ca4ec588e54d002e58495c",
                ciphertext: "ba8ae31bc506486d6873e4fce460e7dc57591ff00611f31c3834fe1c04ad80b66803afcf5b27e6333fa67c99da47c2f0ced68d531bd741a943cff7a6713bd0",
                tag: "2611cd7daa01d61c5c886dc1a8170107",
                hashKey: "9a5e559a96459c21e43c0dff0fa426f3",
                gHash: "177e93a6a2287a8e2d2ec236372101b8"),
        };

        //
        // Helpers
        //

        // Negative index to start from the back
        private static byte[] Modified(byte[] data, int index)
        {
            var modified = new byte[data.Length];
            data.CopyTo(modified, 0);
            ++modified[index < 0 ? data.Length + index : index];

            return modified;
        }
    }
}
