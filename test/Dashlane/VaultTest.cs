// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using PasswordManagerAccess.Dashlane;
using Shouldly;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class VaultTest : TestBase
    {
        [Fact]
        public void Open_throws_on_user_not_found()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("error-user-not-found"));

            // Act/Assert
            Exceptions.AssertThrowsBadCredentials(
                () => Vault.Open(Username, Password, new ThrowingUi(), MakeEmptyStorage(), flow),
                "The given login does not exist."
            );
        }

        [Fact]
        public void Open_returns_accounts_with_existing_device_keys()
        {
            // Arrange
            var flow = new RestFlow().Post(GetFixture("non-empty-vault"));

            // Act
            var vault = Vault.Open(Username, Password, new ThrowingUi(), MakeStorage(), flow);

            // Assert
            vault.Accounts.ShouldNotBeEmpty();
        }

        [Fact]
        public void Open_returns_accounts_with_totp_device_registration()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-totp"))
                .Post(GetFixture("perform-otp-verification"))
                .Post(GetFixture("complete-device-registration-with-auth-ticket"))
                .Post(GetFixture("non-empty-vault"));

            // Act
            var vault = Vault.Open(Username, Password, MakeUi(Otp, false), MakeEmptyStorage(), flow);

            // Assert
            vault.Accounts.ShouldNotBeEmpty();
        }

        [Fact]
        public void Open_returns_accounts_after_retry_on_failed_otp()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-totp"))
                .Post(GetFixture("error-verification-failed"))
                .Post(GetFixture("perform-otp-verification"))
                .Post(GetFixture("complete-device-registration-with-auth-ticket"))
                .Post(GetFixture("non-empty-vault"));

            // Act
            var vault = Vault.Open(
                Username,
                Password,
                MakeUi(new Ui.Passcode(WrongOtp, false), new Ui.Passcode(Otp, false)),
                MakeEmptyStorage(),
                flow
            );

            // Assert
            vault.Accounts.ShouldNotBeEmpty();
        }

        [Theory]
        [InlineData("")]
        [InlineData("1")]
        [InlineData("12345")]
        [InlineData("12345a")]
        [InlineData("1234567")]
        public void Open_asks_ui_for_another_token_when_it_is_not_6_digits(string token)
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-totp"))
                .Post(GetFixture("perform-otp-verification"))
                .Post(GetFixture("complete-device-registration-with-auth-ticket"))
                .Post(GetFixture("non-empty-vault"));

            // Act
            var vault = Vault.Open(Username, Password, MakeUi(new Ui.Passcode(token, false), new Ui.Passcode(Otp, false)), MakeEmptyStorage(), flow);

            // Assert
            vault.Accounts.ShouldNotBeEmpty();
        }

        [Fact]
        public void Open_saves_device_keys_when_remember_me_is_true()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-totp"))
                .Post(GetFixture("perform-otp-verification"))
                .Post(GetFixture("complete-device-registration-with-auth-ticket"))
                .Post(GetFixture("non-empty-vault"));

            var storage = MakeEmptyStorage();

            // Act
            Vault.Open(Username, Password, MakeUi(Otp, true), storage, flow);

            // Assert
            storage.Values.ShouldContainKeyAndValue("device-access-key", "7a9ba9207cb36988");
            storage.Values.ShouldContainKeyAndValue("device-secret-key", "583ac4dc6c6ea8b9380ca03d095b51cd15f178bad10715d7ba67f06f47e63995");
        }

        [Fact]
        public void Open_does_not_save_device_keys_when_remember_me_is_false()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-totp"))
                .Post(GetFixture("perform-otp-verification"))
                .Post(GetFixture("complete-device-registration-with-auth-ticket"))
                .Post(GetFixture("non-empty-vault"));

            var storage = MakeEmptyStorage();

            // Act
            Vault.Open(Username, Password, MakeUi(Otp, false), storage, flow);

            // Assert
            storage.Values["device-access-key"].ShouldBe("");
            storage.Values["device-secret-key"].ShouldBe("");
        }

        [Fact]
        public void Open_opens_vault_with_server_key()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-totp"))
                .Post(GetFixture("perform-otp-verification"))
                .Post(GetFixture("complete-device-registration-with-server-key"))
                .Post(GetFixture("non-empty-vault-with-server-key"));

            // Act
            var vault = Vault.Open(UsernameWithServerKey, PasswordWithServerKey, MakeUi(Otp, false), MakeEmptyStorage(), flow);

            // Assert
            vault.Accounts.ShouldNotBeEmpty();
        }

        [Fact]
        public void Open_with_server_ignores_remember_me_and_does_not_save_device_keys()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-totp"))
                .Post(GetFixture("perform-otp-verification"))
                .Post(GetFixture("complete-device-registration-with-server-key"))
                .Post(GetFixture("non-empty-vault-with-server-key"));

            var storage = MakeEmptyStorage();

            // Act
            Vault.Open(UsernameWithServerKey, PasswordWithServerKey, MakeUi(Otp, true), storage, flow);

            // Assert
            storage.Values["device-access-key"].ShouldBe("");
            storage.Values["device-secret-key"].ShouldBe("");
        }

        [Fact]
        public void Open_returns_accounts_with_email_token_device_registration()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-email"))
                .Post(GetFixture("perform-otp-verification"))
                .Post(GetFixture("complete-device-registration-with-auth-ticket"))
                .Post(GetFixture("non-empty-vault"));

            // Act
            var vault = Vault.Open(Username, Password, MakeUi(new Ui.Passcode(Otp, false)), MakeEmptyStorage(), flow);

            // Assert
            vault.Accounts.ShouldNotBeEmpty();
        }

        [Fact]
        public void Open_returns_accounts_after_retry_on_failed_email_token()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-email"))
                .Post(GetFixture("error-verification-failed"))
                .Post(GetFixture("perform-otp-verification"))
                .Post(GetFixture("complete-device-registration-with-auth-ticket"))
                .Post(GetFixture("non-empty-vault"));

            // Act
            var vault = Vault.Open(
                Username,
                Password,
                MakeUi(new Ui.Passcode(WrongOtp, false), new Ui.Passcode(Otp, false)),
                MakeEmptyStorage(),
                flow
            );

            // Assert
            vault.Accounts.ShouldNotBeEmpty();
        }

        [Fact]
        public void Open_succeeds_after_two_failed_otp_attempts_and_third_successful()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-totp"))
                .Post(GetFixture("error-verification-failed"))
                .Post(GetFixture("error-verification-failed"))
                .Post(GetFixture("perform-otp-verification"))
                .Post(GetFixture("complete-device-registration-with-auth-ticket"))
                .Post(GetFixture("non-empty-vault"));

            // Act
            var vault = Vault.Open(
                Username,
                Password,
                MakeUi(new Ui.Passcode(WrongOtp, false), new Ui.Passcode(WrongOtp, false), new Ui.Passcode(Otp, false)),
                MakeEmptyStorage(),
                flow
            );

            // Assert
            vault.Accounts.ShouldNotBeEmpty();
        }

        [Fact]
        public void Open_throws_canceled_mfa_after_three_wrong_otp_attempts()
        {
            // Arrange
            var flow = new RestFlow()
                .Post(GetFixture("auth-methods-totp"))
                .Post(GetFixture("error-verification-failed"))
                .Post(GetFixture("error-verification-failed"))
                .Post(GetFixture("error-verification-failed"));

            // Act/Assert
            Exceptions.AssertThrowsBadMultiFactor(
                () =>
                    Vault.Open(
                        Username,
                        Password,
                        MakeUi(new Ui.Passcode(WrongOtp, false), new Ui.Passcode(WrongOtp, false), new Ui.Passcode(WrongOtp, false)),
                        MakeEmptyStorage(),
                        flow
                    ),
                "MFA failed too many times"
            );
        }

        // TODO: Add tests to check transactions in the vault.

        //
        // Helpers
        //

        private class SequenceUi(Ui.Passcode[] passcodes, bool loop = false) : Ui
        {
            private int _current;

            public override Passcode ProvideGoogleAuthPasscode(int attempt) => Next();

            public override Passcode ProvideEmailPasscode(int attempt) => Next();

            public override bool OpenInBrowser(string url, int attempt) => true;

            private Passcode Next()
            {
                if (_current >= passcodes.Length)
                    Assert.Fail("SequenceUi: No more passcodes");

                var passcode = passcodes[_current];
                _current++;

                if (loop && _current >= passcodes.Length)
                    _current = 0;

                return passcode;
            }
        }

        private class ThrowingUi : Ui
        {
            public override Passcode ProvideGoogleAuthPasscode(int attempt) => throw new InvalidOperationException("Google Auth passcode");

            public override Passcode ProvideEmailPasscode(int attempt) => throw new InvalidOperationException("Email passcode");

            public override bool OpenInBrowser(string url, int attempt) => throw new InvalidOperationException("Open in browser");
        }

        private static Ui MakeUi(string code, bool rememberMe)
        {
            return new SequenceUi([new Ui.Passcode(code, rememberMe)], true);
        }

        private static Ui MakeUi(params Ui.Passcode[] passcodes)
        {
            return new SequenceUi(passcodes, false);
        }

        private static MemoryStorage MakeStorage() => MakeStorage(AccessKey, SecretKey);

        private static MemoryStorage MakeEmptyStorage() => MakeStorage("", "");

        private static MemoryStorage MakeStorage(string accessKey, string secretKey)
        {
            return new MemoryStorage(new Dictionary<string, string> { ["device-access-key"] = accessKey, ["device-secret-key"] = secretKey });
        }

        //
        // Data
        //

        private const string Username = "lastpass.ruby+17-september-2025@gmail.com";
        private const string Password = "PasswordPassword123!?";
        private const string UsernameWithServerKey = "lastpass.ruby+26-september-2025@gmail.com";
        private const string PasswordWithServerKey = "PasswordPassword123!?";
        private const string AccessKey = "access-key";
        private const string SecretKey = "secret-key";
        private const string Otp = "123456";
        private const string WrongOtp = "654321";
    }
}
