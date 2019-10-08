// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Xml.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class ImportTest
    {
        public const string Password = "password";
        public const string DeviceId = "local-uki";
        public const string LocalKeyFilename = "Dashlane/Fixtures/localKey.aes";
        public const string SettingsFilename = "Dashlane/Fixtures/localSettings.aes";
        public const string Xml =
            "<root>" +
                "<KWLocalSettingsManager>" +
                    "<KWDataItem key='uki'>local-uki</KWDataItem>" +
                "</KWLocalSettingsManager>" +
            "</root>";

        [Fact]
        public void ImportDeviceIdFromSettingsFile_returns_device_id()
        {
            Assert.Equal(DeviceId, Import.ImportDeviceIdFromSettingsFile(SettingsFilename, Password.ToBytes()));
        }

        [Fact]
        public void ImportDeviceIdFromSettings_as_xml_string_returns_device_id()
        {
            Assert.Equal(DeviceId, Import.ImportDeviceIdFromSettings(Xml));
        }

        [Fact]
        public void ImportDeviceIdFromSettings_as_xml_string_throws_on_invalid_xml()
        {
            Exceptions.AssertThrowsInternalError(() => Import.ImportDeviceIdFromSettings("> not really xml <"),
                                                 "Failed to parse XML settings file");
        }

        [Fact]
        public void ImportDeviceIdFromSettings_as_xdocument_returns_device_id()
        {
            Assert.Equal(DeviceId, Import.ImportDeviceIdFromSettings(XDocument.Parse(Xml)));
        }

        [Fact]
        public void ImportDeviceIdFromSettings_as_xdocument_throws_on_wrong_xml()
        {
            Exceptions.AssertThrowsInternalError(() => Import.ImportDeviceIdFromSettings(XDocument.Parse("<root />")),
                                                 "The settings file doesn't contain a device ID");
        }

        [Fact]
        public void ImportLocalKey_loads_and_decrypts_key()
        {
            var key = Import.ImportLocalKey(LocalKeyFilename, "Password13");
            Assert.Equal(32, key.Length);
        }

        [Fact]
        public void ImportLocalKey_throws_on_incorrect_password()
        {
            Exceptions.AssertThrowsBadCredentials(() => Import.ImportLocalKey(LocalKeyFilename, "Incorrect password"),
                                                  "The password is incorrect");
        }

        [Fact]
        public void LoadSettingsFile_reads_and_decrypts_settings_xml()
        {
            var s = Import.LoadSettingsFile(SettingsFilename, Password.ToBytes());
            Assert.StartsWith("<?xml", s);
            Assert.EndsWith("</root>\n", s);
        }

        [Fact]
        public void LoadSettingsFile_throws_on_incorrect_key()
        {
            Exceptions.AssertThrowsBadCredentials(
                () => Import.LoadSettingsFile(SettingsFilename, "Incorrect key".ToBytes()),
                "The password is incorrect");
        }
    }
}
