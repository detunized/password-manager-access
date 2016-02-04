// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.IO;
using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class ImportTest
    {
        private const string Passowrd = "password";

        [Test]
        public void LoadSettings_reads_and_decrypts_settings_xml()
        {
            Assert.That(
                Import.LoadSettings("Fixtures/localSettings.aes", Passowrd),
                Is.StringStarting("<?xml").And.StringEnding("</root>\n"));
        }
    }
}
