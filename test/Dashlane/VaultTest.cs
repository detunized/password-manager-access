// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using Moq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class VaultTest: TestBase
    {
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

        [Fact(Skip = "TODO: Migrate fixtures")]
        public void GenerateRandomDeviceId_returns_device_id()
        {
            var id = Vault.GenerateRandomDeviceId();

            Assert.Equal(69, id.Length);

            var parts = id.Split('-');
            Assert.Equal(6, parts.Length);
            Assert.All(parts, p => Assert.Matches("^[0-9a-f]+$", p));
        }

        //
        // Helpers
        //

        class OtpProvidingUi: Ui
        {
            public override Passcode ProvideGoogleAuthPasscode(int attempt)
            {
                return new Passcode(Otp, false);
            }

            public override Passcode ProvideEmailPasscode(int attempt)
            {
                throw new NotImplementedException();
            }
        }

        class Storage: ISecureStorage
        {
            public string LoadString(string name) => "";
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
