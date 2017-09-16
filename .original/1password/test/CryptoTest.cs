// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using NUnit.Framework;

namespace OnePassword.Test
{
    [TestFixture]
    public class CryptoTest
    {
        [Test]
        public void RandomBytes_returns_array_of_requested_size()
        {
            foreach (var size in new[] {0, 1, 2, 3, 4, 15, 255, 1024, 1337})
                Assert.That(Crypto.RandomBytes(size).Length, Is.EqualTo(size));
        }

        [Test]
        public void RandomUuid_returns_string_of_26_characters()
        {
            Assert.That(Crypto.RandomUuid().Length, Is.EqualTo(26));
        }

        [Test]
        public void Sha256_string_returns_hashed_message()
        {
            Assert.That(Crypto.Sha256("message"),
                        Is.EqualTo("q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64()));
        }

        [Test]
        public void Sha256_bytes_returns_hashed_message()
        {
            Assert.That(Crypto.Sha256("message".ToBytes()),
                        Is.EqualTo("q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64()));
        }

        [Test]
        public void Hamc256_string_returns_hashed_message()
        {
            Assert.That(Crypto.Hmac256("salt".ToBytes(), "message"),
                        Is.EqualTo("3b8WZhUCYErLcNYqWWvzwomOHB0vZS6seUq4xfkSSd0=".Decode64()));
        }

        [Test]
        public void Hmac256_bytes_returns_hashed_message()
        {
            Assert.That(Crypto.Hmac256("salt".ToBytes(), "message".ToBytes()),
                        Is.EqualTo("3b8WZhUCYErLcNYqWWvzwomOHB0vZS6seUq4xfkSSd0=".Decode64()));
        }

        [Test]
        public void Hkdf_returns_derived_key()
        {
            Assert.That(Crypto.Hkdf("PBES2g-HS256", "ikm".ToBytes(), "salt".ToBytes()),
                        Is.EqualTo("UybCHXHHQRaFxUUR3G2ZO9CJ0H2eWJ1Ik_MpNQHrHdE".Decode64()));
        }

        [Test]
        public void Pbes2_returns_derived_key()
        {
            Assert.That(Crypto.Pbes2("PBES2g-HS256", "password", "salt".ToBytes(), 100),
                        Is.EqualTo("B-aZcYDPfxKQTwQQDUBdNIiP32KvbVBqDswjsZb-mdg".Decode64()));
            Assert.That(Crypto.Pbes2("PBES2g-HS512", "password", "salt".ToBytes(), 100),
                        Is.EqualTo("_vcnaxBwQKCnE7y-yf0-GRzGFTJJ4kWj4aIgh9vmFgY".Decode64()));
        }

        [Test]
        public void Pbes2_throws_on_unsupported_method()
        {
            Assert.That(() => Crypto.Pbes2("Unknown", "password", "salt".ToBytes(), 100),
                        Throws.TypeOf<InvalidOperationException>());
        }

        [Test]
        public void CalculateSessionHmacSalt_returns_salt()
        {
            var key = new AesKey("", "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM".Decode64());
            var expected =
                "cce080cc9b3eaeaa9b6e621e1b4c4d2048babe16e40b0576fc2520c26473b9ac".DecodeHex();

            Assert.That(Crypto.CalculateSessionHmacSalt(key), Is.EqualTo(expected));
        }

        [Test]
        public void CalculateClientHash_returns_hash()
        {
            Assert.That(Crypto.CalculateClientHash(TestData.ClientInfo, TestData.Session),
                        Is.EqualTo("SnO6NuEoGdflPsCV9nue0po8CGNwidfN_DExidLZ-uA"));
        }
    }
}
