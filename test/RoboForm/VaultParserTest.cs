// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace RoboForm.Test
{
    [TestFixture]
    class VaultParserTest
    {
        [Test]
        public void Parse_returns_vault()
        {
            var vault = VaultParser.Parse(JObject.Parse(TestData.DecryptedBlob));
            Assert.That(vault.Accounts.Length, Is.GreaterThan(1));
        }
    }
}
