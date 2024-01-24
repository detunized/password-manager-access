// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Net;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class VaultTest: TestBase
    {
        [Fact]
        public void Open_returns_accounts_with_existing_device_id()
        {
            var flow = new RestFlow().Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   null,
                                   new Storage(Uki),
                                   flow);

            Assert.NotEmpty(vault.Accounts);
        }

        [Fact]
        public void Open_returns_accounts_with_email_token_and_device_registration()
        {
            var flow = new RestFlow()
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("email-token-triggered"))
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   MakeUi(Otp, false),
                                   new Storage(""),
                                   flow);

            Assert.NotEmpty(vault.Accounts);
        }

        [Fact]
        public void Open_returns_accounts_with_otp_token_and_device_registration()
        {
            var flow = new RestFlow()
                .Post(GetFixture("otp-requested"))
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   MakeUi(Otp, false),
                                   new Storage(""),
                                   flow);

            Assert.NotEmpty(vault.Accounts);
        }

        [Fact]
        public void Open_throws_on_resend_with_totp()
        {
            var flow = new RestFlow()
                .Post(GetFixture("otp-requested"));

            Exceptions.AssertThrowsInternalError(() => Vault.Open(Username,
                                                                  Password,
                                                                  MakeUi(Ui.Passcode.Resend),
                                                                  new Storage(""),
                                                                  flow),
                                                 "Return value Resend is invalid in this context");
        }

        [Fact]
        public void Open_returns_accounts_with_email_token_and_device_registration_with_expired_device_id()
        {
            var flow = new RestFlow()
                .Post(GetFixture("invalid-uki"))
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("email-token-triggered"))
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   MakeUi(Otp, false),
                                   new Storage(Uki),
                                   flow);

            Assert.NotEmpty(vault.Accounts);
        }

        [Fact]
        public void Open_returns_accounts_with_otp_token_and_device_registration_with_expired_device_id()
        {
            var flow = new RestFlow()
                .Post(GetFixture("invalid-uki"))
                .Post(GetFixture("otp-requested"))
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   MakeUi(Otp, false),
                                   new Storage(Uki),
                                   flow);

            Assert.NotEmpty(vault.Accounts);
        }

        [Fact]
        public void Open_throws_on_invalid_email_address()
        {
            var flow = new RestFlow()
                .Post(GetFixture("invalid-email"), HttpStatusCode.BadRequest);

            Exceptions.AssertThrowsBadCredentials(
                () => Vault.Open(Username,
                                 Password,
                                 MakeUi(Otp, false),
                                 new Storage(""),
                                 flow),
                "Invalid username: ");
        }

        [Fact]
        public void Open_returns_accounts_with_email_token_after_1_resend()
        {
            var flow = new RestFlow()
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("email-token-triggered")) // First token trigger
                .Post(GetFixture("email-token-triggered")) // Resend
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   MakeUi(Ui.Passcode.Resend, new Ui.Passcode(Otp, false)),
                                   new Storage(""),
                                   flow);

            Assert.NotEmpty(vault.Accounts);
        }

        [Theory]
        [InlineData("")]
        [InlineData("1")]
        [InlineData("12345")]
        [InlineData("12345a")]
        [InlineData("1234567")]
        public void Open_asks_ui_for_another_token_when_it_is_not_6_digits(string token)
        {
            var flow = new RestFlow()
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("email-token-triggered"))
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   MakeUi(new Ui.Passcode(token, false), new Ui.Passcode(Otp, false)),
                                   new Storage(""),
                                   flow);

            Assert.NotEmpty(vault.Accounts);
        }

        [Fact]
        public void Open_returns_accounts_with_email_token_after_2_bad_attempts()
        {
            var flow = new RestFlow()
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("email-token-triggered"))
                .Post(GetFixture("invalid-email-token"), HttpStatusCode.BadRequest)
                .Post(GetFixture("invalid-email-token"), HttpStatusCode.BadRequest)
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   MakeUi(Otp, false),
                                   new Storage(""),
                                   flow);

            Assert.NotEmpty(vault.Accounts);
        }

        [Fact]
        public void Open_throws_on_invalid_email_token_after_3_attempts()
        {
            var flow = new RestFlow()
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("invalid-email-token"), HttpStatusCode.BadRequest)
                .Post(GetFixture("invalid-email-token"), HttpStatusCode.BadRequest)
                .Post(GetFixture("invalid-email-token"), HttpStatusCode.BadRequest);

            Exceptions.AssertThrowsBadMultiFactor(
                () => Vault.Open(Username,
                                 Password,
                                 MakeUi(Otp, false),
                                 new Storage(""),
                                 flow),
                "MFA failed: ");
        }

        [Theory]
        [InlineData(false, "")]
        [InlineData(true, "5d95e3ccccaa40a1-9cf2dbfd517b6b85ab0a7e2cb23972a195aeef5440db095c187782ea0d349962")]
        public void Open_respects_remember_me_option(bool rememberMe, string expectedDeviceId)
        {
            var flow = new RestFlow()
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("email-token-triggered"))
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var storage = new Storage("");

            Vault.Open(Username,
                       Password,
                       MakeUi(Otp, rememberMe),
                       storage,
                       flow);

            Assert.Equal(expectedDeviceId, storage.Values["device-uki"]);
        }

        [Fact]
        public void Open_erases_invalid_uki()
        {
            var flow = new RestFlow()
                .Post(GetFixture("invalid-uki"))
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("email-token-triggered"))
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var storage = new Storage("invalid-uki");

            var vault = Vault.Open(Username,
                                   Password,
                                   MakeUi(Otp, false),
                                   storage,
                                   flow);

            Assert.Equal("", storage.Values["device-uki"]);
        }

        [Fact]
        public void Open_opens_empty_vault()
        {
            Assert.Empty(Accounts("empty-vault"));
        }

        [Fact]
        public void Open_opens_a_vault_with_empty_fullfile_and_one_add_transaction()
        {
            Assert.Equal(new[]{Dude}, Accounts("empty-fullfile-one-add-transaction"));
        }

        [Fact]
        public void Open_opens_a_vault_with_empty_fullfile_and_two_add_transations()
        {
            Assert.Equal(new[]{Dude, Nam}, Accounts("empty-fullfile-two-add-transactions"));
        }

        [Fact]
        public void Open_opens_a_vault_with_empty_fullfile_and_two_add_and_one_remove_transations()
        {
            Assert.Equal(new[]{Dude, Nam}, Accounts("empty-fullfile-two-add-one-remove-transactions"));
        }

        [Fact]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile()
        {
            Assert.Equal(new[]{Dude, Nam}, Accounts("two-accounts-in-fullfile"));
        }

        [Fact]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile_and_one_remove_transaction()
        {
            Assert.Equal(new[]{Dude}, Accounts("two-accounts-in-fullfile-one-remove-transaction"));
        }

        [Fact]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile_and_two_remove_transactions()
        {
            Assert.Empty(Accounts("two-accounts-in-fullfile-two-remove-transactions"));
        }

        [Fact]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile_and_two_remove_and_one_add_transactions()
        {
            Assert.Equal(new[]{Dude}, Accounts("two-accounts-in-fullfile-two-remove-one-add-transactions"));
        }

        //
        // Helpers
        //

        class SequenceUi: Ui
        {
            private readonly bool _loop;
            private readonly Passcode[] _passcodes;
            private int _current;

            public SequenceUi(Passcode[] passcodes, bool loop = false)
            {
                _passcodes = passcodes;
                _loop = loop;
            }

            public override Passcode ProvideGoogleAuthPasscode(int attempt) => Next();
            public override Passcode ProvideEmailPasscode(int attempt) => Next();

            private Passcode Next()
            {
                if (_current >= _passcodes.Length)
                    Assert.Fail("SequenceUi: No more passcodes");

                var passcode = _passcodes[_current];
                _current++;

                if (_loop && _current >= _passcodes.Length)
                    _current = 0;

                return passcode;
            }
        }

        Ui MakeUi(string code, bool rememberMe)
        {
            return new SequenceUi(new[] { new Ui.Passcode(code, rememberMe) }, true);
        }

        Ui MakeUi(params Ui.Passcode[] passcodes)
        {
            return new SequenceUi(passcodes, false);
        }

        class Storage: ISecureStorage
        {
            public Dictionary<string, string> Values { get; } = new Dictionary<string, string>();

            public Storage(string deviceId)
            {
                StoreString("device-uki", deviceId);
            }

            public string LoadString(string name)
            {
                return Values[name];
            }

            public void StoreString(string name, string value)
            {
                Values[name] = value;
            }
        }

        private string[] Accounts(string filename)
        {
            var flow = new RestFlow().Post(GetFixture(filename));
            return Vault.Open(Username, Password, null, new Storage(Uki), flow)
                .Accounts
                .Select(i => i.Name)
                .ToArray();
        }

        //
        // Data
        //

        private const string Username = "username";
        private const string Password = "password";
        private const string Uki = "uki";

        private const string Dude = "dude.com";
        private const string Nam = "nam.com";

        private const string Otp = "123456";
    }
}
