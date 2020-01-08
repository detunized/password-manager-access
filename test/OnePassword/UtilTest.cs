// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.OnePassword;
using Xunit;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class UtilTest
    {
        [Fact]
        public void RandomUuid_returns_string_of_26_characters()
        {
            Assert.Equal(26, Util.RandomUuid().Length);
        }

        [Fact]
        public void Hkdf_returns_derived_key()
        {
            Assert.Equal("UybCHXHHQRaFxUUR3G2ZO9CJ0H2eWJ1Ik_MpNQHrHdE".Decode64Loose(),
                         Util.Hkdf("PBES2g-HS256", "ikm".ToBytes(), "salt".ToBytes()));
        }

        [Fact]
        public void Pbes2_returns_derived_key()
        {
            Assert.Equal("B-aZcYDPfxKQTwQQDUBdNIiP32KvbVBqDswjsZb-mdg".Decode64Loose(),
                         Util.Pbes2("PBES2g-HS256", "password", "salt".ToBytes(), 100));
            Assert.Equal("_vcnaxBwQKCnE7y-yf0-GRzGFTJJ4kWj4aIgh9vmFgY".
                         Decode64Loose(), Util.Pbes2("PBES2g-HS512", "password", "salt".ToBytes(), 100));
        }

        [Fact]
        public void Pbes2_throws_on_unsupported_method()
        {
            Exceptions.AssertThrowsUnsupportedFeature(() => Util.Pbes2("Unknown", "password", "salt".ToBytes(), 100),
                                                      "Method 'Unknown' is not supported");
        }

        [Fact]
        public void CalculateSessionHmacSalt_returns_salt()
        {
            var key = new AesKey("", "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM".Decode64Loose());
            var expected = "cce080cc9b3eaeaa9b6e621e1b4c4d2048babe16e40b0576fc2520c26473b9ac".DecodeHex();

            Assert.Equal(expected, Util.CalculateSessionHmacSalt(key));
        }

        [Fact]
        public void CalculateClientHash_convenience_returns_hash()
        {
            Assert.Equal("SnO6NuEoGdflPsCV9nue0po8CGNwidfN_DExidLZ-uA", Util.CalculateClientHash(TestData.Session));
        }

        [Fact]
        public void CalculateClientHash_returns_hash()
        {
            Assert.Equal("SnO6NuEoGdflPsCV9nue0po8CGNwidfN_DExidLZ-uA",
                         Util.CalculateClientHash("RTN9SA", "TOZVTFIFBZGFDFNE5KSZFY7EZY"));
        }

        [Fact]
        public void HashRememberMeToken_convenience_returns_hash()
        {
            Assert.Equal("XPvm9ASr", Util.HashRememberMeToken("ZBcCUphmNqw-DNB45PKIbw", TestData.Session));
        }

        [Fact]
        public void HashRememberMeToken_returns_hash()
        {
            Assert.Equal("oNk_XW_e",
                         Util.HashRememberMeToken("ZBcCUphmNqw-DNB45PKIbw", "HPI33B234JDIHCRKHCO3LDDIII"));
        }
    }
}
