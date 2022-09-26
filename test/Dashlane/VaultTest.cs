// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using System.Net;
using Moq;
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
                                   new Storage { DeviceId = Uki },
                                   flow);

            Assert.NotEmpty(vault.Accounts);
        }

        [Fact]
        public void Open_returns_accounts_with_email_token_and_device_registration()
        {
            var flow = new RestFlow()
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   new OtpProvidingUi { Code = Otp, RememberMe = false },
                                   new Storage { DeviceId = "" },
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
                                   new OtpProvidingUi { Code = Otp, RememberMe = false },
                                   new Storage { DeviceId = "" },
                                   flow);

            Assert.NotEmpty(vault.Accounts);
        }

        [Fact]
        public void Open_returns_accounts_with_email_token_and_device_registration_with_expired_device_id()
        {
            var flow = new RestFlow()
                .Post(GetFixture("invalid-uki"))
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   new OtpProvidingUi { Code = Otp, RememberMe = false },
                                   new Storage { DeviceId = Uki },
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
                                   new OtpProvidingUi { Code = Otp, RememberMe = false },
                                   new Storage { DeviceId = Uki },
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
                                 new OtpProvidingUi { Code = Otp, RememberMe = false },
                                 new Storage { DeviceId = "" },
                                 flow),
                "Invalid username: ");
        }

        [Fact]
        public void Open_returns_accounts_with_email_token_after_2_bad_attempts()
        {
            var flow = new RestFlow()
                .Post(GetFixture("email-token-sent"))
                .Post(GetFixture("invalid-email-token"), HttpStatusCode.BadRequest)
                .Post(GetFixture("invalid-email-token"), HttpStatusCode.BadRequest)
                .Post(GetFixture("email-token-verified"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("non-empty-vault"));

            var vault = Vault.Open(Username,
                                   Password,
                                   new OtpProvidingUi { Code = Otp, RememberMe = false },
                                   new Storage { DeviceId = "" },
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
                                 new OtpProvidingUi { Code = Otp, RememberMe = false },
                                 new Storage { DeviceId = "" },
                                 flow),
                "MFA failed: ");
        }

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void Open_opens_empty_vault()
        {
            Assert.Empty(Accounts("empty-vault"));
        }

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void Open_opens_a_vault_with_empty_fullfile_and_one_add_transaction()
        {
            Assert.Equal(new[]{Dude}, Accounts("empty-fullfile-one-add-transaction"));
        }

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void Open_opens_a_vault_with_empty_fullfile_and_two_add_transations()
        {
            Assert.Equal(new[]{Dude, Nam}, Accounts("empty-fullfile-two-add-transactions"));
        }

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void Open_opens_a_vault_with_empty_fullfile_and_two_add_and_one_remove_transations()
        {
            Assert.Equal(new[]{Dude, Nam}, Accounts("empty-fullfile-two-add-one-remove-transactions"));
        }

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile()
        {
            Assert.Equal(new[]{Dude, Nam}, Accounts("two-accounts-in-fullfile"));
        }

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile_and_one_remove_transaction()
        {
            Assert.Equal(new[]{Dude}, Accounts("two-accounts-in-fullfile-one-remove-transaction"));
        }

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile_and_two_remove_transactions()
        {
            Assert.Empty(Accounts("two-accounts-in-fullfile-two-remove-transactions"));
        }

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile_and_two_remove_and_one_add_transactions()
        {
            Assert.Equal(new[]{Dude}, Accounts("two-accounts-in-fullfile-two-remove-one-add-transactions"));
        }

        //
        // MFA
        //

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void Open_calls_gets_opt_from_ui()
        {
            var flow = new RestFlow()
                .Post(GetFixture("exists-otp"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("empty-vault"))
                    .ExpectContent($"otp={Otp}");

            var ui = new Mock<Ui>();
            ui.Setup(x => x.ProvideGoogleAuthPasscode(It.IsAny<int>())).Returns(new Ui.Passcode(Otp, false));

            Vault.Open(Username, Password, ui.Object, new Storage(), flow);
        }

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void Open_throws_on_user_canceled_otp()
        {
            var flow = new RestFlow()
                .Post(GetFixture("exists-otp"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture("empty-vault"));

            var ui = new Mock<Ui>();
            ui.Setup(x => x.ProvideGoogleAuthPasscode(It.IsAny<int>())).Returns(Ui.Passcode.Cancel);

            Exceptions.AssertThrowsCanceledMultiFactor(() => Vault.Open(Username, Password, ui.Object, new Storage(), flow),
                                                       "MFA canceled by the user");
        }

        //
        // Helpers
        //

        class OtpProvidingUi: Ui
        {
            public string Code { get; set; }
            public bool RememberMe { get; set; }

            public override Passcode ProvideGoogleAuthPasscode(int attempt) => new Passcode(Code, RememberMe);
            public override Passcode ProvideEmailPasscode(int attempt) => new Passcode(Code, RememberMe);
        }

        class Storage: ISecureStorage
        {
            public string DeviceId { get; set; }

            public string LoadString(string name) => DeviceId;
            public void StoreString(string name, string value) {}
        }

        private string[] Accounts(string filename)
        {
            var flow = new RestFlow()
                .Post(GetFixture("exists-yes"))
                .Post(GetFixture("device-registered"))
                .Post(GetFixture(filename));
            return Vault.Open(Username, Password, null, new Storage(), flow)
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

        private const string Otp = "1337";
    }
}
