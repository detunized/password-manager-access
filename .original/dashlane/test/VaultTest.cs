// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Specialized;
using System.IO;
using System.Linq;
using Moq;
using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class VaultTest
    {
        public const string Username = "username";
        public const string Password = "password";
        public const string Uki = "uki";

        public const string Dude = "dude.com";
        public const string Nam = "nam.com";

        [Test]
        public void Open_opens_empty_vault()
        {
            Assert.That(Accounts("empty-vault"), Is.Empty);
        }

        [Test]
        public void Open_opens_a_vault_with_empty_fullfile_and_one_add_transaction()
        {
            Assert.That(
                Accounts("empty-fullfile-one-add-transaction"),
                Is.EqualTo(new[] {Dude}));
        }

        [Test]
        public void Open_opens_a_vault_with_empty_fullfile_and_two_add_transations()
        {
            Assert.That(
                Accounts("empty-fullfile-two-add-transactions"),
                Is.EqualTo(new[] {Dude, Nam}));
        }

        [Test]
        public void Open_opens_a_vault_with_empty_fullfile_and_two_add_and_one_remove_transations()
        {
            Assert.That(
                Accounts("empty-fullfile-two-add-one-remove-transactions"),
                Is.EqualTo(new[] {Dude, Nam}));
        }

        [Test]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile()
        {
            Assert.That(
                Accounts("two-accounts-in-fullfile"),
                Is.EqualTo(new[] {Dude, Nam}));
        }

        [Test]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile_and_one_remove_transaction()
        {
            Assert.That(
                Accounts("two-accounts-in-fullfile-one-remove-transaction"),
                Is.EqualTo(new[] {Dude}));
        }

        [Test]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile_and_two_remove_transactions()
        {
            Assert.That(
                Accounts("two-accounts-in-fullfile-two-remove-transactions"),
                Is.Empty);
        }

        [Test]
        public void Open_opens_a_vault_with_two_accounts_in_fullfile_and_two_remove_and_one_add_transactions()
        {
            Assert.That(
                Accounts("two-accounts-in-fullfile-two-remove-one-add-transactions"),
                Is.EqualTo(new[] {Dude}));
        }

        //
        // Helpers
        //

        private static string[] Accounts(string filename)
        {
            return Vault.Open(Username, Password, Uki, SetupWebClient(filename))
                .Accounts
                .Select(i => i.Name)
                .ToArray();
        }

        private static IWebClient SetupWebClient(string filename)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Returns(File.ReadAllBytes(string.Format("Fixtures/{0}.json", filename)));

            return webClient.Object;
        }
    }
}
