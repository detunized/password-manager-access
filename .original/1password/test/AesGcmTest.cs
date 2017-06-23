// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class AesGcmTest
    {
        [Test]
        public void Encrypt()
        {
            foreach (var i in TestCases)
            {
                var ciphertext = AesGcm.Encrypt(i.Key, i.Plaintext, i.Iv, i.AuthData);
                Assert.That(ciphertext, Is.EqualTo(i.Expected));
            }
        }

        [Test]
        public void GHash()
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
            public readonly byte[] Expected;

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
                Expected = (ciphertext + tag).DecodeHex();

                HashKey = hashKey.DecodeHex();
                GHash = gHash.DecodeHex();
            }
        }

        // TODO: Add more tests from http://www.ieee802.org/1/files/public/docs2011/bn-randall-test-vectors-0511-v1.pdf
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
        };
    }
}
