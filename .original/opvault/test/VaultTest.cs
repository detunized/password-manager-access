// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;
using NUnit.Framework;

namespace OPVault.Test
{
    [TestFixture]
    public class VaultTest
    {
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
            Assert.That(folders["1D3B2B341F7A43F6A316179F4216E731"].Type, Is.EqualTo(JTokenType.Object));
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
                        Throws.InvalidOperationException);
        }

        [Test]
        public void LoadJsAsJsonFromString_throws_on_missing_prefix()
        {
            Assert.That(() => Vault.LoadJsAsJsonFromString("var j = {};", "-", ";"),
                        Throws.InvalidOperationException);
        }

        [Test]
        public void LoadJsAsJsonFromString_throws_on_missing_suffix()
        {
            Assert.That(() => Vault.LoadJsAsJsonFromString("var j = {};", "var j =", "-"),
                        Throws.InvalidOperationException);
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
    }
}
