// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.OnePassword;
using R = PasswordManagerAccess.OnePassword.Response;
using Util = PasswordManagerAccess.OnePassword.Util;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class UtilTest : TestBase
    {
        [Fact]
        public void RandomUuid_returns_string_of_26_characters()
        {
            Assert.Equal(26, Util.RandomUuid().Length);
        }

        [Fact]
        public void Hkdf_returns_derived_key()
        {
            Assert.Equal("UybCHXHHQRaFxUUR3G2ZO9CJ0H2eWJ1Ik_MpNQHrHdE".Decode64Loose(), Util.Hkdf("PBES2g-HS256", "ikm".ToBytes(), "salt".ToBytes()));
        }

        [Fact]
        public void Pbes2_returns_derived_key()
        {
            Assert.Equal(
                "B-aZcYDPfxKQTwQQDUBdNIiP32KvbVBqDswjsZb-mdg".Decode64Loose(),
                Util.Pbes2("PBES2g-HS256", "password", "salt".ToBytes(), 100)
            );
            Assert.Equal(
                "_vcnaxBwQKCnE7y-yf0-GRzGFTJJ4kWj4aIgh9vmFgY".Decode64Loose(),
                Util.Pbes2("PBES2g-HS512", "password", "salt".ToBytes(), 100)
            );
        }

        [Fact]
        public void Pbes2_throws_on_unsupported_method()
        {
            Exceptions.AssertThrowsUnsupportedFeature(
                () => Util.Pbes2("Unknown", "password", "salt".ToBytes(), 100),
                "Method 'Unknown' is not supported"
            );
        }

        [Fact]
        public void CalculateSessionHmacSalt_returns_salt()
        {
            var key = new AesKey("", "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM".Decode64Loose());
            var expected = "cce080cc9b3eaeaa9b6e621e1b4c4d2048babe16e40b0576fc2520c26473b9ac".DecodeHex();

            Assert.Equal(expected, Util.CalculateSessionHmacSalt(key));
        }

        [Fact]
        public void CalculateClientHash_returns_hash()
        {
            Assert.Equal("SnO6NuEoGdflPsCV9nue0po8CGNwidfN_DExidLZ-uA", Util.CalculateClientHash("RTN9SA", "TOZVTFIFBZGFDFNE5KSZFY7EZY"));
        }

        [Fact]
        public void HashRememberMeToken_returns_hash()
        {
            Assert.Equal("oNk_XW_e", Util.HashRememberMeToken("ZBcCUphmNqw-DNB45PKIbw", "HPI33B234JDIHCRKHCO3LDDIII"));
        }

        [Fact]
        public void DecryptAesKey_adds_decrypted_key_to_keychain()
        {
            var encrypted = ParseFixture<R.Encrypted>("encrypted-aes-key");
            var keychain = new Keychain(new AesKey("mp", "44c38e8fedb84a1ab5ba74ed98dde931f6500ae39c1d9c85e20a7268ab2074f0".DecodeHex()));

            Util.DecryptAesKey(encrypted, keychain);
            var k = keychain.GetAes("szerdhg2ww2ahjo4ilz57x7cce").Key.ToHex();

            Assert.NotNull(keychain.GetAes("szerdhg2ww2ahjo4ilz57x7cce"));
        }

        [Fact]
        public void DecryptRsaKey_adds_decrypted_key_to_keychain()
        {
            var encrypted = ParseFixture<R.Encrypted>("encrypted-rsa-key");
            var keychain = new Keychain(
                new AesKey("szerdhg2ww2ahjo4ilz57x7cce", "bba932f6032dc4dffaa9b8f03c9fd4b810127b89a49408db7b914a131690c091".DecodeHex())
            );

            Util.DecryptRsaKey(encrypted, keychain);

            Assert.NotNull(keychain.GetRsa("szerdhg2ww2ahjo4ilz57x7cce"));
        }

        [Theory]
        [InlineData("my.1password.com", "com")]
        [InlineData("my.1password.eu", "eu")]
        [InlineData("my.1password.ca", "ca")]
        [InlineData(".1password.xyz", "xyz")]
        [InlineData("1password.xyz", "xyz")]
        [InlineData(".xyz", "xyz")]
        [InlineData("xyz", "xyz")]
        [InlineData(".", "")]
        [InlineData("", "")]
        public void GetTld_returns_tld(string domain, string expected)
        {
            Assert.Equal(expected, Util.GetTld(domain));
        }

        [Fact]
        public void ThrowUi_throws_on_method_call()
        {
            var ui = new Util.ThrowUi();
            AssertLogicError(() => ui.ChooseDuoFactor([], [], CancellationToken.None));
            AssertLogicError(() => ui.ProvideDuoPasscode(new DuoDevice("", "", []), CancellationToken.None));
            AssertLogicError(() => ui.UpdateDuoStatus(DuoStatus.Info, "", CancellationToken.None));
            AssertLogicError(() => ui.ProvideGoogleAuthPasscode(CancellationToken.None));
            AssertLogicError(() => ui.ProvideWebAuthnRememberMe(CancellationToken.None));
        }

        [Fact]
        public void ThrowStorage_throws_on_method_call()
        {
            var storage = new Util.ThrowStorage();
            AssertLogicError(() => storage.LoadString(""));
            AssertLogicError(() => storage.StoreString("", ""));
        }

        //
        // Helper
        //

        static void AssertLogicError(Action f)
        {
            Exceptions.AssertThrowsInternalError(f, "Logic error");
        }
    }
}
