// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Xml;
using System.Xml.Linq;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class ImportTest
    {
        public const string Passowrd = "password";
        public const string Uki = "local-uki";
        public const string Filename = "Dashlane/Fixtures/localSettings.aes";
        public const string Xml =
            "<root>" +
                "<KWLocalSettingsManager>" +
                    "<KWDataItem key='uki'>local-uki</KWDataItem>" +
                "</KWLocalSettingsManager>" +
            "</root>";

        [Fact]
        public void ImportUkiFromSettingsFile_returns_uki()
        {
            Assert.Equal(Uki, Import.ImportUkiFromSettingsFile(Filename, Passowrd));
        }

        [Fact]
        public void ImportUkiFromSettings_as_xml_string_returns_uki()
        {
            Assert.Equal(Uki, Import.ImportUkiFromSettings(Xml));
        }

        [Fact]
        public void ImportUkiFromSettings_as_xml_string_throws_on_invalid_xml()
        {
            var e = Assert.Throws<ImportException>(() => Import.ImportUkiFromSettings("> not really xml <"));

            Assert.Equal(ImportException.FailureReason.InvalidFormat, e.Reason);
            Assert.Equal("Failed to parse XML settings file", e.Message);
            Assert.IsType<XmlException>(e.InnerException);
        }

        [Fact]
        public void ImportUkiFromSettings_as_xdocument_returns_uki()
        {
            Assert.Equal(Uki, Import.ImportUkiFromSettings(XDocument.Parse(Xml)));
        }

        [Fact]
        public void ImportUkiFromSettings_as_xdocument_throws_on_wrong_xml()
        {
            var e = Assert.Throws<ImportException>(() => Import.ImportUkiFromSettings(XDocument.Parse("<root />")));

            Assert.Equal(ImportException.FailureReason.InvalidFormat, e.Reason);
            Assert.Equal("The settings file doesn't contain an UKI", e.Message);
            Assert.Null(e.InnerException);
        }

        [Fact]
        public void LoadSettingsFile_reads_and_decrypts_settings_xml()
        {
            var s = Import.LoadSettingsFile(Filename, Passowrd);
            Assert.StartsWith("<?xml", s);
            Assert.EndsWith("</root>\n", s);
        }

        [Fact]
        public void LoadSettingsFile_throws_on_incorrect_password()
        {
            var e = Assert.Throws<ImportException>(() => Import.LoadSettingsFile(Filename, "Incorrect password"));

            Assert.Equal(ImportException.FailureReason.IncorrectPassword, e.Reason);
            Assert.Equal("The settings file is corrupted or the password is incorrect", e.Message);
            Assert.IsType<ParseException>(e.InnerException);
        }
    }
}
