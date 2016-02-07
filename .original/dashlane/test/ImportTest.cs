// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Xml;
using System.Xml.Linq;
using NUnit.Framework;

namespace Dashlane.Test
{
    [TestFixture]
    class ImportTest
    {
        public const string Passowrd = "password";
        public const string Uki = "local-uki";
        public const string Filename = "Fixtures/localSettings.aes";
        public const string Xml =
            "<root>" +
                "<KWLocalSettingsManager>" +
                    "<KWDataItem key='uki'>local-uki</KWDataItem>" +
                "</KWLocalSettingsManager>" +
            "</root>";

        [Test]
        public void ImportUkiFromSettingsFile_returns_uki()
        {
            Assert.That(
                Import.ImportUkiFromSettingsFile(Filename, Passowrd),
                Is.EqualTo(Uki));
        }

        [Test]
        public void ImportUkiFromSettings_as_xml_string_returns_uki()
        {
            Assert.That(
                Import.ImportUkiFromSettings(Xml),
                Is.EqualTo(Uki));
        }

        [Test]
        public void ImportUkiFromSettings_as_xml_string_throws_on_invalid_xml()
        {
            Assert.That(
                () => Import.ImportUkiFromSettings("> not really xml <"),
                Throws
                    .TypeOf<ImportException>()
                    .And.Property("Reason").EqualTo(ImportException.FailureReason.InvalidFormat)
                    .And.Message.EqualTo("Failed to parse XML settings file")
                    .And.InnerException.InstanceOf<XmlException>());
        }

        [Test]
        public void ImportUkiFromSettings_as_xdocument_returns_uki()
        {
            Assert.That(
                Import.ImportUkiFromSettings(XDocument.Parse(Xml)),
                Is.EqualTo(Uki));
        }

        [Test]
        public void ImportUkiFromSettings_as_xdocument_throws_on_wrong_xml()
        {
            Assert.That(
                () => Import.ImportUkiFromSettings(XDocument.Parse("<root />")),
                Throws
                    .TypeOf<ImportException>()
                    .And.Property("Reason").EqualTo(ImportException.FailureReason.InvalidFormat)
                    .And.Message.EqualTo("The settings file doesn't contain an UKI"));
        }

        [Test]
        public void LoadSettingsFile_reads_and_decrypts_settings_xml()
        {
            Assert.That(
                Import.LoadSettingsFile(Filename, Passowrd),
                Is.StringStarting("<?xml").And.StringEnding("</root>\n"));
        }
    }
}
