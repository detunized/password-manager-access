// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;
using Crypto = PasswordManagerAccess.OnePassword.Crypto;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class CryptoTest
    {
        [Fact]
        public void RandomUuid_returns_string_of_26_characters()
        {
            Assert.Equal(26, Crypto.RandomUuid().Length);
        }

        [Fact]
        public void Sha256_string_returns_hashed_message()
        {
            Assert.Equal("q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64Loose(),
                         Crypto.Sha256("message"));
        }

        [Fact]
        public void Sha256_bytes_returns_hashed_message()
        {
            Assert.Equal("q1MKE+RZFJgrefm34/uplM/R8/si9xzqGvvwK0YMbR0=".Decode64Loose(),
                         Crypto.Sha256("message".ToBytes()));
        }

        [Fact]
        public void Hamc256_string_returns_hashed_message()
        {
            Assert.Equal("3b8WZhUCYErLcNYqWWvzwomOHB0vZS6seUq4xfkSSd0=".Decode64Loose(),
                         Crypto.Hmac256("salt".ToBytes(), "message"));
        }

        [Fact]
        public void Hmac256_bytes_returns_hashed_message()
        {
            Assert.Equal("3b8WZhUCYErLcNYqWWvzwomOHB0vZS6seUq4xfkSSd0=".Decode64Loose(),
                         Crypto.Hmac256("salt".ToBytes(), "message".ToBytes()));
        }

        [Fact]
        public void Hkdf_returns_derived_key()
        {
            Assert.Equal("UybCHXHHQRaFxUUR3G2ZO9CJ0H2eWJ1Ik_MpNQHrHdE".Decode64Loose(),
                         Crypto.Hkdf("PBES2g-HS256", "ikm".ToBytes(), "salt".ToBytes()));
        }

        [Fact]
        public void Pbes2_returns_derived_key()
        {
            Assert.Equal("B-aZcYDPfxKQTwQQDUBdNIiP32KvbVBqDswjsZb-mdg".Decode64Loose(),
                         Crypto.Pbes2("PBES2g-HS256", "password", "salt".ToBytes(), 100));
            Assert.Equal("_vcnaxBwQKCnE7y-yf0-GRzGFTJJ4kWj4aIgh9vmFgY".
                         Decode64Loose(), Crypto.Pbes2("PBES2g-HS512", "password", "salt".ToBytes(), 100));
        }

        [Fact]
        public void Pbes2_throws_on_unsupported_method()
        {
            var e = Assert.Throws<ClientException>(() => Crypto.Pbes2("Unknown", "password", "salt".ToBytes(), 100));
            Assert.Equal(ClientException.FailureReason.UnsupportedFeature, e.Reason);
            Assert.Contains("method", e.Message);
        }

        [Fact]
        public void CalculateSessionHmacSalt_returns_salt()
        {
            var key = new AesKey("", "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM".Decode64Loose());
            var expected = "cce080cc9b3eaeaa9b6e621e1b4c4d2048babe16e40b0576fc2520c26473b9ac".DecodeHex();

            Assert.Equal(expected, Crypto.CalculateSessionHmacSalt(key));
        }

        [Fact]
        public void CalculateClientHash_convenience_returns_hash()
        {
            Assert.Equal("SnO6NuEoGdflPsCV9nue0po8CGNwidfN_DExidLZ-uA", Crypto.CalculateClientHash(TestData.Session));
        }

        [Fact]
        public void CalculateClientHash_returns_hash()
        {
            Assert.Equal("SnO6NuEoGdflPsCV9nue0po8CGNwidfN_DExidLZ-uA",
                         Crypto.CalculateClientHash("RTN9SA", "TOZVTFIFBZGFDFNE5KSZFY7EZY"));
        }

        [Fact]
        public void HashRememberMeToken_convenience_returns_hash()
        {
            Assert.Equal("XPvm9ASr", Crypto.HashRememberMeToken("ZBcCUphmNqw-DNB45PKIbw", TestData.Session));
        }

        [Fact]
        public void HashRememberMeToken_returns_hash()
        {
            Assert.Equal("oNk_XW_e",
                         Crypto.HashRememberMeToken("ZBcCUphmNqw-DNB45PKIbw", "HPI33B234JDIHCRKHCO3LDDIII"));
        }
    }
}
