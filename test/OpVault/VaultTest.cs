// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PasswordManagerAccess.OpVault;
using Xunit;
using M = PasswordManagerAccess.OpVault.Model;

namespace PasswordManagerAccess.Test.OpVault
{
    public class VaultTest
    {
        [Fact]
        public void Official_test_vault_works()
        {
            var accounts = Vault.Open(OfficialTestVaultPath, OfficialTestPassword);
            Assert.Equal(10, accounts.Length);
        }

        [Fact]
        public void Open_returns_accounts()
        {
            var accounts = Vault.Open(TestVaultPath, Password);
            Assert.Equal(3, accounts.Length);
        }

        [Fact]
        public void Open_supports_nested_folders()
        {
            var accounts = Vault.Open(TestVaultPath, Password);
            var childFolder = accounts.First(i => i.Folder.Name == "Even Cooler Stuff").Folder;

            Assert.Equal("Cool Stuff", childFolder.Parent.Name);
        }

        [Fact]
        public void Open_throws_on_invalid_path()
        {
            Exceptions.AssertThrowsInternalError(() => Vault.Open("does/not/exist", Password), "doesn't exist");
        }

        [Fact]
        public void Open_throws_on_incorrect_password()
        {
            Exceptions.AssertThrowsBadCredentials(() => Vault.Open(TestVaultPath, "incorrect password"),
                                                  "password is incorrect");
        }

        [Fact]
        public void Open_throws_on_corrupted_vault()
        {
            Exceptions.AssertThrowsInternalError(() => Vault.Open(CorruptedVaultPath, Password), "corrupted");
        }

        [Fact]
        public void LoadProfile_reads_profile_js()
        {
            var profile = Vault.LoadProfile(TestVaultPath);
            Assert.Equal("pzJ5y/CiCeU8Sbo8+k4/zg==", profile.Salt);
            Assert.Equal(40000, profile.Iterations);
        }

        [Theory]
        [InlineData("{}")]
        [InlineData("{'iterations': 1, 'masterKey': '', 'overviewKey': ''}")] // 'salt' is missing
        [InlineData("{'salt':'', 'masterKey': '', 'overviewKey': ''}")] // 'iterations' is missing
        [InlineData("{'salt':'', 'iterations': 1, 'overviewKey': ''}")] // 'masterKey' is missing
        [InlineData("{'salt':'', 'iterations': 1, 'masterKey': ''}")] // 'overviewKey' is missing
        [InlineData("{'salt': null, 'iterations': 1, 'masterKey': '', 'overviewKey': ''}")] // 'salt' is null
        [InlineData("{'salt':'', 'iterations': null, 'masterKey': '', 'overviewKey': ''}")] // 'iterations' is null
        [InlineData("{'salt':'', 'iterations': 1, 'masterKey': null, 'overviewKey': ''}")] // 'masterKey' is null
        [InlineData("{'salt':'', 'iterations': 1, 'masterKey': null, 'overviewKey': null}")] // 'overviewKey' is null
        public void LoadProfile_throws_on_invalid_json_schema(string json)
        {
            WithTempVault(
                "profile.js",
                $"var profile={json};",
                path => Exceptions.AssertThrowsInternalError(
                    () => Vault.LoadProfile(path),
                    "Invalid JSON schema for Profile"));
        }

        [Fact]
        public void LoadFolders_reads_folders_js()
        {
            var folders = Vault.LoadFolders(TestVaultPath);
            Assert.Equal(3, folders.Length);
        }

        [Fact]
        public void LoadFolders_Deleted_defaults_to_false_when_missing()
        {
            WithTempVault(
                "folders.js",
                "loadFolders({'a': {'uuid': 'a', 'overview': ''}});",
                path =>
                {
                    var folders = Vault.LoadFolders(path);
                    Assert.Single(folders);
                    Assert.False(folders[0].Deleted);
                });
        }

        [Theory]
        [InlineData("{'a': {}}")]
        [InlineData("{'a': {'overview': ''}}")] // 'uuid' is missing
        [InlineData("{'a': {'uuid': 'a'}}")]  // 'overview' is missing
        [InlineData("{'a': {'uuid': null, 'overview': ''}}")]  // 'uuid' is null
        [InlineData("{'a': {'uuid': 'a', 'overview': null}}")] // 'overview' is null
        [InlineData("{'a': {'uuid': 'a', 'overview': '', trashed: null}}")] // 'trashed' is null
        public void LoadFolders_throws_on_invalid_json_schema(string json)
        {
            WithTempVault(
                "folders.js",
                $"loadFolders({json});",
                path => Exceptions.AssertThrowsInternalError(
                    () => Vault.LoadFolders(path),
                    "Invalid JSON schema for Dictionary`2")); // TODO: Non-descriptive generic name
        }

        [Fact]
        public void LoadItems_reads_items_from_all_bands()
        {
            var items = Vault.LoadItems(TestVaultPath);
            Assert.Equal(3, items.Length);
        }

        [Fact]
        public void LoadItems_Deleted_defaults_to_false_when_missing()
        {
            WithTempVault(
                "band_7.js",
                "ld({'a': {'uuid': 'a', 'k': '', 'o': '', 'd': ''}});",
                path =>
                {
                    var items = Vault.LoadItems(path);
                    Assert.Single(items);
                    Assert.False(items[0].Deleted);
                });
        }

        [Theory]
        [InlineData("{'a': {}}")]
        [InlineData("{'a': {'k': '', 'o': '', 'd': ''}}")] // 'uuid' is missing
        [InlineData("{'a': {'uuid': 'a', 'o': '', 'd': ''}}")] // 'k' is missing
        [InlineData("{'a': {'uuid': 'a', 'k': '', 'd': ''}}")] // 'o' is missing
        [InlineData("{'a': {'uuid': 'a', 'k': '', 'o': ''}}")] // 'd' is missing
        [InlineData("{'a': {'uuid': null, 'k': '', 'o': '', 'd': ''}}")] // 'uuid' is null
        [InlineData("{'a': {'uuid': 'a', 'k': null, 'o': '', 'd': ''}}")] // 'k' is null
        [InlineData("{'a': {'uuid': 'a', 'k': '', 'o': null, 'd': ''}}")] // 'o' is null
        [InlineData("{'a': {'uuid': 'a', 'k': '', 'o': '', 'd': null}}")] // 'd' is null
        [InlineData("{'a': {'uuid': 'a', 'k': '', 'o': '', 'd': '', trashed: null}}")] // 'trashed' is null
        public void LoadItems_throws_on_invalid_json_schema(string json)
        {
            WithTempVault(
                "band_7.js",
                $"ld({json});",
                path => Exceptions.AssertThrowsInternalError(
                    () => Vault.LoadItems(path),
                    "Invalid JSON schema for Dictionary`2")); // TODO: Non-descriptive generic name
        }

        [Fact]
        public void LoadJsAsJson_reads_json_from_file()
        {
            var json = Vault.LoadJsAsJson<M.Profile>($"{TestVaultPath}/default/profile.js", "var profile=", ";");
            Assert.Equal("pzJ5y/CiCeU8Sbo8+k4/zg==", json.Salt);
        }

        [Fact]
        public void LoadJsAsJsonFromString_returns_parsed_json_object()
        {
            var expected = new KeyValuePair<string, string>("key", "value");
            var json = Vault.LoadJsAsJsonFromString<KeyValuePair<string, string>>(
                "var j = {'Key': 'key', 'Value': 'value'};",
                "var j = ",
                ";");

            Assert.Equal(expected, json);
        }

        [Fact]
        public void LoadJsAsJsonFromString_throws_on_too_short_input()
        {
            Exceptions.AssertThrowsInternalError(
                () => Vault.LoadJsAsJsonFromString<object>("-", "var j = ", ";"),
                "too short");
        }

        [Fact]
        public void LoadJsAsJsonFromString_throws_on_missing_prefix()
        {
            Exceptions.AssertThrowsInternalError(
                () => Vault.LoadJsAsJsonFromString<object>("var j = {};", "-", ";"),
                "prefix is not found");
        }

        [Fact]
        public void LoadJsAsJsonFromString_throws_on_missing_suffix()
        {
            Exceptions.AssertThrowsInternalError(
                () => Vault.LoadJsAsJsonFromString<object>("var j = {};", "var j =", "-"),
                "suffix is not found");
        }

        [Fact]
        public void MakeFilename_makes_path_inside_vault()
        {
            var expected = Path.DirectorySeparatorChar switch
            {
                '/' => "path/to/test.opvault/default/profile.js",
                '\\' => "path\\to\\test.opvault\\default\\profile.js",
                _ => throw new InvalidOperationException("Unknown directory separator"),
            };
            var filename = Vault.MakeFilename("path/to/test.opvault", "profile.js");

            Assert.Equal(expected, filename);
        }

        [Fact]
        public void MakeFilename_ignores_extra_slash()
        {
            var expected = Path.DirectorySeparatorChar switch
            {
                '/' => "path/to/test.opvault/default/profile.js",
                '\\' => "path\\to\\test.opvault\\default\\profile.js",
                _ => throw new InvalidOperationException("Unknown directory separator"),
            };
            var filename = Vault.MakeFilename("path/to/test.opvault/", "profile.js");

            Assert.Equal(expected, filename);
        }

        [Fact]
        public void MakeFilename_keeps_drive_letter()
        {
            var expected = Path.DirectorySeparatorChar switch
            {
                '/' => "c:/path/to/test.opvault/default/profile.js",
                '\\' => "c:\\path\\to\\test.opvault\\default\\profile.js",
                _ => throw new InvalidOperationException("Unknown directory separator"),
            };
            var filename = Vault.MakeFilename("c:/path/to/test.opvault", "profile.js");

            Assert.Equal(expected, filename);
        }

        [Fact]
        public void NormalizeSlashes_converts_forward_to_back_slashes_on_windows()
        {
            // This test is only valid on Windows, there's no slash conversion on Linux/Mac
            if (Path.DirectorySeparatorChar == '\\')
            {
                var normalized = Vault.NormalizeSlashes("/path/to\\a/file/");
                Assert.Equal("\\path\\to\\a\\file\\", normalized);
            }
        }

        [Fact]
        public void DecryptJson_returns_decrypted_and_deserialized_object()
        {
            var result = Vault.DecryptJson<M.ItemOverview>(EncryptedItemOverview, ItemOverviewKey);

            Assert.Equal("facebook.com", result.Title);
            Assert.Equal("http://facebook.com", result.Url);
        }

        [Fact]
        public void DecryptJson_throws_on_bad_schema()
        {
            // We need to use a type here with some required properties that are missing in the encrypted data
            Exceptions.AssertThrowsInternalError(
                () => Vault.DecryptJson<M.Item>(EncryptedItemOverview, ItemOverviewKey),
                "JSON: Invalid JSON schema for Item");
        }

        //
        // Helpers
        //

        // TODO: Refactor the Vault code to accept the file content, not the filename.
        //       Then we wouldn't need to create temporary files.
        private static void WithTempVault(string filename, string content, Action<string> block)
        {
            var path = Path.Combine(Path.GetTempPath(), Path.GetRandomFileName());
            var dir = Directory.CreateDirectory(path);
            try
            {
                var def = dir.CreateSubdirectory("default");
                File.WriteAllText(Path.Combine(def.FullName, filename), content);
                block(dir.FullName);
            }
            finally
            {
                dir.Delete(true);
            }
        }

        //
        // Data
        //

        private const string FixturePath = "OpVault/Fixtures/";
        private const string TestVaultPath = FixturePath + "test.opvault";
        private const string CorruptedVaultPath = FixturePath + "corrupted.opvault";
        private const string Password = "password";

        // From here: https://cache.agilebits.com/security-kb/
        private const string OfficialTestVaultPath = FixturePath + "onepassword_data";
        private const string OfficialTestPassword = "freddy";

        private const string EncryptedItemOverview = "b3BkYXRhMDFvAAAAAAAAAABUfMSKAQo2xA4jIxRdDsuUSk9uQmJouYHJ5CT6CIg" +
                                                     "Y3DZd7qrc2VejvzfkMLVTaZI9DRHdgS75LG16kL8xaUmVtGk2ZqnVWJ2UA8y4S6" +
                                                     "QPdjoWzJLJbiYvGhYicNYgK5A2WzFTrCXPT2vQfHzZeh2gJohM4ZI5wmpHPN5Xc" +
                                                     "hepRpyIptYTjkyg0ssLjSISul9j/4vuP4FDwH9W6Vr31JQ=";
        private static readonly KeyMac ItemOverviewKey = new KeyMac("oMDgYulnpl83PKSEycLJg1fqkvxqU3bo4MliEGlN12i4" +
                                                                    "eUt7qRdl06zVKKbxRLAnra3TvKz0LDdZnV/hlQkjBQ==");

    }
}
