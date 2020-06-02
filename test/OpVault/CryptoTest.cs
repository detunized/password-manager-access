// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using NUnit.Framework;

namespace OPVault.Test
{
    [TestFixture]
    public class CryptoTest
    {
        [Test]
        public void DeriveKek_returns_key()
        {
            var expected = new KeyMac("a7HZUoTh0E9I7LCTF3AHDRQXGEbcnQuUMv6Vcvv7e13IOFMfmCJORzuf" +
                                      "hnDVeB4cDrxnTsPFYMTvpHboE8MPGg==");
            var kek = Crypto.DeriveKek("password".ToBytes(), "pzJ5y/CiCeU8Sbo8+k4/zg==".Decode64(), 40000);

            Assert.That(kek.Key, Is.EqualTo(expected.Key));
            Assert.That(kek.MacKey, Is.EqualTo(expected.MacKey));
        }

        [Test]
        public void Sha512_returns_hashed_message()
        {
            var expected = "+Nr1ejNHzE1rnVdbMf5gd+LLSH9gqWIzwIy0edvzFTjMkV7G1IvbqpbdwaFttPT5bzcnbPyzUQuCRiQXcNWVLA==";

            // Generated with OpenSSL (just a smoke test, we're not implementing SHA here)
            // $ echo -n message | openssl dgst -sha512 -binary | openssl base64
            Assert.That(Crypto.Sha512("message".ToBytes()), Is.EqualTo(expected.Decode64()));
        }

        [Test]
        public void Hmac_returns_hashed_message()
        {
            // Generated with OpenSSL (just a smoke test, we're not implementing HMAC here)
            // $ echo -n message | openssl dgst -sha256 -binary -hmac "saltsaltsaltsaltsaltsaltsaltsalt" | openssl base64
            Assert.That(Crypto.Hmac("message".ToBytes(), TestKey),
                        Is.EqualTo("drZnXZBwtFUIqm8vnAtCXXWSRmHl4qt9E0tqT4kok7Q=".Decode64()));
        }

        [Test]
        public void DecryptAes_returns_plaintext_without_padding()
        {
            // Generated with Ruby/openssl
            Assert.That(Crypto.DecryptAes("yNVOKI5bgIJ0lPdVszvlEQ==".Decode64(),
                                          "iviviviviviviviv".ToBytes(),
                                          TestKey),
                        Is.EqualTo("decrypted data!!".ToBytes()));
        }

        //
        // Data
        //

        private static readonly KeyMac TestKey =
            new KeyMac("key!key!key!key!key!key!key!key!saltsaltsaltsaltsaltsaltsaltsalt".ToBytes());
    }
}
