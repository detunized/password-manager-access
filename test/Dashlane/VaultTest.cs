// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using Moq;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class VaultTest: TestBase
    {
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
        // MFA
        //

        [Fact]
        public void Open_calls_gets_opt_from_ui()
        {
            var flow = new RestFlow()
                .Post(GetFixture("exists-otp"))
                .Post(GetFixture("empty-vault"))
                    .ExpectContent($"otp={Otp}");

            var ui = new Mock<Ui>();
            ui.Setup(x => x.ProvideGoogleAuthPasscode(It.IsAny<int>())).Returns(new Ui.Passcode(Otp, false));

            Vault.Open(Username, Password, Uki, ui.Object, flow);
        }

        [Fact]
        public void Open_throws_on_user_canceled_otp()
        {
            var flow = new RestFlow()
                .Post(GetFixture("exists-otp"))
                .Post(GetFixture("empty-vault"));

            var ui = new Mock<Ui>();
            ui.Setup(x => x.ProvideGoogleAuthPasscode(It.IsAny<int>())).Returns(Ui.Passcode.Cancel);

            Exceptions.AssertThrowsCanceledMultiFactor(() => Vault.Open(Username, Password, Uki, ui.Object, flow),
                                                       "MFA canceled by the user");
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
        }

        private string[] Accounts(string filename)
        {
            var flow = new RestFlow()
                .Post(GetFixture("exists-yes"))
                .Post(GetFixture(filename));
            return Vault.Open(Username, Password, Uki, null, flow)
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
