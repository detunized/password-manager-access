// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace OPVault.Test
{
    [TestFixture]
    public class VaultTest
    {
        [Test]
        public void Open_returns_accounts()
        {
            var accounts = Vault.Open(TestVaultPath, Password);
            Assert.That(accounts.Length, Is.EqualTo(3));
        }

        [Test]
        public void Open_supprts_nested_folders()
        {
            var accounts = Vault.Open(TestVaultPath, Password);
            var childFolder = accounts.First(i => i.Folder.Name == "Even Cooler Stuff").Folder;

            Assert.That(childFolder.Parent.Name, Is.EqualTo("Cool Stuff"));
        }

        [Test]
        public void Open_throws_on_invalid_path()
        {
            Assert.That(() => Vault.Open("does/not/exist", Password),
                        ExceptionsTest.ThrowsFileNotFoundWithMessage("doesn't exist"));
        }

        [Test]
        public void LoadProfile_reads_profile_js()
        {
            var profile = Vault.LoadProfile(TestVaultPath);
            Assert.That((string)profile["uuid"], Is.EqualTo("714A14D7017048CC9577AD050FC9C6CA"));
        }

        [Test]
        public void LoadFolders_reads_folders_js()
        {
            var folders = Vault.LoadFolders(TestVaultPath);
            Assert.That(folders.Length, Is.EqualTo(3));
        }

        [Test]
        public void LoadItems_reads_items_from_all_bands()
        {
            var items = Vault.LoadItems(TestVaultPath);
            Assert.That(items.Length, Is.EqualTo(3));
        }

        [Test]
        public void LoadJsAsJson_reads_json_from_file()
        {
            var json = Vault.LoadJsAsJson(string.Format("{0}/default/profile.js", TestVaultPath), "var profile=", ";");
            Assert.That((string)json["uuid"], Is.EqualTo("714A14D7017048CC9577AD050FC9C6CA"));
        }

        [Test]
        public void LoadJsAsJsonFromString_returns_parsed_json_object()
        {
            var expected = JObject.Parse("{'key': 'value'}");
            var json = Vault.LoadJsAsJsonFromString("var j = {'key': 'value'};", "var j = ", ";");

            Assert.That(JToken.DeepEquals(json, expected));
        }

        [Test]
        public void LoadJsAsJsonFromString_throws_on_too_short_input()
        {
            Assert.That(() => Vault.LoadJsAsJsonFromString("-", "var j = ", ";"),
                        ExceptionsTest.ThrowsInvalidFormatWithMessage("too short"));
        }

        [Test]
        public void LoadJsAsJsonFromString_throws_on_missing_prefix()
        {
            Assert.That(() => Vault.LoadJsAsJsonFromString("var j = {};", "-", ";"),
                        ExceptionsTest.ThrowsInvalidFormatWithMessage("prefix is not found"));
        }

        [Test]
        public void LoadJsAsJsonFromString_throws_on_missing_suffix()
        {
            Assert.That(() => Vault.LoadJsAsJsonFromString("var j = {};", "var j =", "-"),
                        ExceptionsTest.ThrowsInvalidFormatWithMessage("suffix is not found"));
        }

        [Test]
        public void MakeFilename_makes_path_inside_vault()
        {
            var filename = Vault.MakeFilename("path/to/test.opvault", "profile.js");
            Assert.That(filename, Is.EqualTo("path\\to\\test.opvault\\default\\profile.js"));
        }

        [Test]
        public void MakeFilename_ignores_extra_slash()
        {
            var filename = Vault.MakeFilename("path/to/test.opvault/", "profile.js");
            Assert.That(filename, Is.EqualTo("path\\to\\test.opvault\\default\\profile.js"));
        }

        [Test]
        public void MakeFilename_keeps_drive_letter()
        {
            var filename = Vault.MakeFilename("c:/path/to/test.opvault", "profile.js");
            Assert.That(filename, Is.EqualTo("c:\\path\\to\\test.opvault\\default\\profile.js"));
        }

        [Test]
        public void NormalizeSlashes_converts_forward_to_back_slashes()
        {
            // TODO: Test on non Windows based platforms
            var normalized = Vault.NormalizeSlashes("/path/to\\a/file/");
            Assert.That(normalized, Is.EqualTo("\\path\\to\\a\\file\\"));
        }

        //
        // Data
        //

        private const string TestVaultPath = "test.opvault";
        private const string Password = "password";
    }
}
