// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Specialized;
using System.IO;
using Moq;
using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class VaultTest
    {
        public readonly string Username = "username";
        public readonly string Password = "password";
        public readonly string Uki = "uki";

        [Test]
        public void Open_opens_empty_vault()
        {
            Assert.That(
                Vault.Open(Username, Password, Uki, SetupWebClient("{}")).Accounts,
                Is.Empty);
        }

        //
        // Helpers
        //

        private static IWebClient SetupWebClient(string response)
        {
            var webClient = new Mock<IWebClient>();
            webClient
                .Setup(x => x.UploadValues(It.IsAny<string>(), It.IsAny<NameValueCollection>()))
                .Returns(response.ToBytes());

            return webClient.Object;
        }
    }
}
