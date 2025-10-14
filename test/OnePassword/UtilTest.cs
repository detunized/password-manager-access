// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Duo;
using PasswordManagerAccess.OnePassword;
using Shouldly;
using Xunit;
using Util = PasswordManagerAccess.OnePassword.Util;

namespace PasswordManagerAccess.Test.OnePassword
{
    public class UtilTest : TestBase
    {
        [Fact]
        public void RandomUuid_returns_string_of_26_characters()
        {
            // Arrange/Act
            var result = Util.RandomUuid().Length;

            // Assert
            result.ShouldBe(26);
        }

        [Fact]
        public void Hkdf_returns_derived_key()
        {
            // Arrange
            var method = "PBES2g-HS256";
            var ikm = "ikm".ToBytes();
            var salt = "salt".ToBytes();
            var expected = "UybCHXHHQRaFxUUR3G2ZO9CJ0H2eWJ1Ik_MpNQHrHdE".Decode64Loose();

            // Act
            var result = Util.Hkdf(method, ikm, salt);

            // Assert
            result.ShouldBe(expected);
        }

        [Theory]
        [InlineData("PBES2g-HS256", "B-aZcYDPfxKQTwQQDUBdNIiP32KvbVBqDswjsZb-mdg")]
        [InlineData("PBES2g-HS512", "_vcnaxBwQKCnE7y-yf0-GRzGFTJJ4kWj4aIgh9vmFgY")]
        public void Pbes2_returns_derived_key(string method, string expectedBase64)
        {
            // Arrange
            var password = "password";
            var salt = "salt".ToBytes();
            var iterations = 100;
            var expected = expectedBase64.Decode64Loose();

            // Act
            var key = Util.Pbes2(method, password, salt, iterations);

            // Assert
            key.ShouldBe(expected);
        }

        [Fact]
        public void Pbes2_throws_on_unsupported_method()
        {
            // Arrange
            var act = () => Util.Pbes2("Unknown", "password", "salt".ToBytes(), 100);

            // Act/Assert
            act.ShouldThrow<UnsupportedFeatureException>().Message.ShouldBe("Method 'Unknown' is not supported");
        }

        [Fact]
        public void CalculateSessionHmacSalt_returns_salt()
        {
            // Arrange
            var key = new AesKey("", "WyICHHlP5lPigZUGZYoivbJMqgHjSti86UKwdjCryYM".Decode64Loose());
            var expected = "cce080cc9b3eaeaa9b6e621e1b4c4d2048babe16e40b0576fc2520c26473b9ac".DecodeHex();

            // Act
            var salt = Util.CalculateSessionHmacSalt(key);

            // Assert
            salt.ShouldBe(expected);
        }

        [Fact]
        public void CalculateClientHash_returns_hash()
        {
            // Arrange
            var accountKeyUuid = "RTN9SA";
            var sessionId = "TOZVTFIFBZGFDFNE5KSZFY7EZY";
            var expected = "SnO6NuEoGdflPsCV9nue0po8CGNwidfN_DExidLZ-uA";

            // Act
            var hash = Util.CalculateClientHash(accountKeyUuid, sessionId);

            // Assert
            hash.ShouldBe(expected);
        }

        [Fact]
        public void HashRememberMeToken_returns_hash()
        {
            // Arrange
            var token = "ZBcCUphmNqw-DNB45PKIbw";
            var sessionId = "HPI33B234JDIHCRKHCO3LDDIII";
            var expected = "oNk_XW_e";

            // Act
            var hash = Util.HashRememberMeToken(token, sessionId);

            // Assert
            hash.ShouldBe(expected);
        }

        [Fact]
        public void DecryptAesKey_adds_decrypted_key_to_keychain()
        {
            // Arrange
            var encrypted = ParseFixture<Model.Encrypted>("encrypted-aes-key", useSystemJson: true);
            var keychain = new Keychain(new AesKey("mp", "44c38e8fedb84a1ab5ba74ed98dde931f6500ae39c1d9c85e20a7268ab2074f0".DecodeHex()));

            // Act
            Util.DecryptAesKey(encrypted, keychain);

            // Assert
            keychain.GetAes("szerdhg2ww2ahjo4ilz57x7cce").ShouldNotBeNull();
        }

        [Fact]
        public void DecryptRsaKey_adds_decrypted_key_to_keychain()
        {
            // Arrange
            var encrypted = ParseFixture<Model.Encrypted>("encrypted-rsa-key", useSystemJson: true);
            var keychain = new Keychain(
                new AesKey("szerdhg2ww2ahjo4ilz57x7cce", "bba932f6032dc4dffaa9b8f03c9fd4b810127b89a49408db7b914a131690c091".DecodeHex())
            );

            // Act
            Util.DecryptRsaKey(encrypted, keychain);

            // Assert
            keychain.GetRsa("szerdhg2ww2ahjo4ilz57x7cce").ShouldNotBeNull();
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
            // Act
            var result = Util.GetTld(domain);

            // Assert
            result.ShouldBe(expected);
        }

        [Fact]
        public async Task ThrowUi_throws_on_method_call()
        {
            // Arrange
            var ui = new Util.ThrowUi();

            // Act/Assert
            await AssertLogicError(() => ui.ChooseDuoFactor([], [], CancellationToken.None));
            await AssertLogicError(() => ui.ProvideDuoPasscode(new DuoDevice("", "", []), CancellationToken.None));
            await AssertLogicError(() => ui.UpdateDuoStatus(DuoStatus.Info, "", CancellationToken.None));
            await AssertLogicError(() => ui.ProvideGoogleAuthPasscode(0, [], CancellationToken.None));
            await AssertLogicError(() => ui.ProvideWebAuthnRememberMe(0, [], CancellationToken.None));
        }

        [Fact]
        public async Task ThrowStorage_throws_on_method_call()
        {
            // Arrange
            var storage = new Util.ThrowStorage();

            // Act & Assert
            await AssertLogicError(() => storage.LoadString(""));
            await AssertLogicError(() => storage.StoreString("", ""));
        }

        //
        // Helper
        //

        private static async Task AssertLogicError(Func<Task> f)
        {
            var ex = await f.ShouldThrowAsync<InternalErrorException>();
            ex.Message.ShouldStartWith("Logic error");
        }
    }
}
