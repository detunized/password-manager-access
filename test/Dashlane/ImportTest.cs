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
        [Theory]
        [InlineData("localSettings-kwc3.aes")]
        [InlineData("localSettings-pbkdf2.aes")]
        [InlineData("localSettings-argon2d.aes")]
        public void ImportDeviceIdFromSettingsFile_returns_device_id(string filename)
        {
            var id = Import.ImportDeviceIdFromSettingsFile($"{FixtureDir}/{filename}", LocalKey);
            Assert.Equal(DeviceId, id);
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

        [Theory]
        [InlineData("localKey-kwc3.aes")]
        [InlineData("localKey-pbkdf2.aes")]
        [InlineData("localKey-argon2d.aes")]
        public void ImportLocalKey_loads_and_decrypts_key(string filename)
        {
            var key = Import.ImportLocalKey($"{FixtureDir}/{filename}", Password);
            Assert.Equal(LocalKey, key);
        }

        [Fact]
        public void ImportLocalKey_throws_on_incorrect_password()
        {
            Exceptions.AssertThrowsBadCredentials(
                () => Import.ImportLocalKey($"{FixtureDir}/localKey-kwc3.aes", "Incorrect password"),
                "The password is incorrect");
        }

        [Fact]
        public void LoadSettingsFile_reads_and_decrypts_settings_xml()
        {
            var s = Import.LoadSettingsFile(SettingsFilename, LocalKey);
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

        //
        // Data
        //

        private const string Password = "Password13";
        private const string DeviceId = "4242424242421997669740r1570532486-2BKZLme8-Euno-7XFl-F09n-JaIvRMHi6h24";
        private const string FixtureDir = "Dashlane/Fixtures";
        private const string SettingsFilename = FixtureDir + "/localSettings-kwc3.aes";

        private readonly byte[] LocalKey = "n+YYHZEKgxghoy3vlJ+EfWyCZ2CTn6Ik3jpGTjhbsbQ=".Decode64();

        private readonly string Xml =
            "<root>" +
                "<KWLocalSettingsManager>" +
                    $"<KWDataItem key='uki'>{DeviceId}</KWDataItem>" +
                "</KWLocalSettingsManager>" +
            "</root>";
    }
}
