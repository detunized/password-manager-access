// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Newtonsoft.Json.Linq;
using PasswordManagerAccess.RoboForm;
using Xunit;

namespace PasswordManagerAccess.Test.RoboForm
{
    public class VaultParserTest: TestBase
    {
        [Theory]
        [InlineData("blob")]
        [InlineData("blob-with-extra-root-siblings")]
        public void Parse_returns_accounts_and_private_key(string fixture)
        {
            var (accounts, privateKey) = VaultParser.Parse(JObject.Parse(GetFixture(fixture)));

            Assert.NotEmpty(accounts);
            Assert.NotNull(privateKey);
        }

        [Theory]
        [InlineData("blob")]
        [InlineData("blob-with-extra-root-siblings")]
        public void Parse_prepends_parent_path(string fixture)
        {
            var parentPath = "blah/blah-blah";
            var (accounts, _) = VaultParser.Parse(JObject.Parse(GetFixture(fixture)), parentPath);

            foreach (var account in accounts)
                Assert.StartsWith(parentPath, account.Path);
        }

        [Theory]
        // Root with no content
        [InlineData(TopLevelPrefix + RootNoContent + TopLevelSuffix)]
        // Root with empty content
        [InlineData(RootPrefix + RootSuffix)]
        // Root with a folder but no accounts
        [InlineData(RootPrefix + "{'i': {'F': true, 'n': 'blah'}}" + RootSuffix)]
        public void Parse_returns_empty_vault(string json)
        {
            var (accounts, _) = VaultParser.Parse(JObject.Parse(json));

            Assert.Empty(accounts);
        }

        [Theory]
        // No private key
        [InlineData(TopLevelPrefix + RootNoContent + TopLevelSuffix)]
        // Private key without data
        [InlineData(TopLevelPrefix + "{'i': {'n': 'private-key.pem'}}, " + RootNoContent + TopLevelSuffix)]
        // Private key with null data
        [InlineData(TopLevelPrefix + "{'i': {'n': 'private-key.pem'}, 'b': null}, " + RootNoContent + TopLevelSuffix)]
        // Private key with blank data
        [InlineData(TopLevelPrefix + "{'i': {'n': 'private-key.pem'}, 'b': ''}, " + RootNoContent + TopLevelSuffix)]
        public void Parse_returns_no_private_key(string json)
        {
            var (_, privateKey) = VaultParser.Parse(JObject.Parse(json));

            Assert.Null(privateKey);
        }

        [Theory]
        // Root with no content
        [InlineData("{'i': {'F': true}, 'c': [{'i': {'F': true, 'n': 'root'}}]}")]
        // Root with empty content
        [InlineData(RootPrefix + RootSuffix)]
        // Root with a folder but no accounts
        [InlineData(RootPrefix + "{'i': {'F': true, 'n': 'blah'}}" + RootSuffix)]
        public void Parse_returns_empty_vault_and_no_private_key(string json)
        {
            var (accounts, privateKey) = VaultParser.Parse(JObject.Parse(json));

            Assert.Empty(accounts);
            Assert.Null(privateKey);
        }

        [Theory]
        [InlineData("{}")]
        [InlineData("{'i': {}, 'c': []}")]
        [InlineData("{'i': {'F': false}, 'c': []}")]
        public void Parse_throws_when_top_level_folder_is_invalid(string json)
        {
            Exceptions.AssertThrowsInternalError(() => VaultParser.Parse(JObject.Parse(json)),
                                                 "Invalid format: top level folder not found");
        }

        [Theory]
        [InlineData("{'i': {'F': true}, 'c': []}")]
        [InlineData("{'i': {'F': true}, 'c': [{'i': {'F': true, 'n': 'blah'}}]}")]
        public void Parse_throws_when_root_folder_is_invalid(string json)
        {
            Exceptions.AssertThrowsInternalError(() => VaultParser.Parse(JObject.Parse(json)),
                                                 "Invalid format: root folder not found");
        }

        [Theory]
        [InlineData("{}")]
        [InlineData("{'i': null}")]
        [InlineData("{'i': 13}")]
        [InlineData("{'i': []}")]
        [InlineData("{'c': {}}")]
        [InlineData("{'b': ''}")]
        public void Parse_throws_when_item_info_block_is_invalid(string json)
        {
            Exceptions.AssertThrowsInternalError(() => VaultParser.Parse(JObject.Parse(RootPrefix + json + RootSuffix)),
                                                 "Invalid format: item info block not found");
        }

        [Theory]
        [InlineData("{}", false)]
        [InlineData("{'i': {}}", false)]
        [InlineData("{'i': {'F': false}}", false)]
        [InlineData("{'i': {'F': true}}", true)]
        [InlineData("{'i': {'F': true}, 'c': []}", true)]
        public void IsFolder_returns_expected_result(string json, bool expected)
        {
            var result = VaultParser.IsFolder(JObject.Parse(json));
            Assert.Equal(expected, result);
        }

        [Theory]
        [InlineData("{'i': {'F': true}, 'c': []}")]
        [InlineData("{'i': {'F': true}, 'c': [{'i': {'F': true}, 'c': []}]}")]
        public void GetFolderContent_returns_content(string json)
        {
            var content = VaultParser.GetFolderContent(JObject.Parse(json));
            Assert.NotNull(content);
        }

        [Theory]
        [InlineData("{}")]
        [InlineData("{'i': {}}")]
        [InlineData("{'i': {'F': false}}")]
        [InlineData("{'i': {'F': true}}")]
        [InlineData("{'i': {'F': true}, 'c': null}")]
        [InlineData("{'i': {'F': true}, 'c': 13}")]
        [InlineData("{'i': {'F': true}, 'c': ''}")]
        [InlineData("{'i': {'F': true}, 'c': {}}")]
        public void GetFolderContent_returns_null(string json)
        {
            var content = VaultParser.GetFolderContent(JObject.Parse(json));
            Assert.Null(content);
        }

        [Theory]
        [InlineData("[{'i': {'n': 'blah'}}]")]
        [InlineData("[{'i': {'n': 'blah'}}, {'i': {'n': 'blah'}}]")]
        [InlineData("[{'i': {'n': 'blah'}}, {'i': {'n': 'blah-blah'}}]")]
        [InlineData("[{'i': {'n': 'blah-blah'}}, {'i': {'n': 'blah'}}]")]
        [InlineData("[{'i': {'n': 'blah-blah'}}, {'i': {'n': 'blah', 'F': true}}]")]
        [InlineData("[{'i': {'n': 'blah-blah'}}, {'i': {'n': 'blah', 'F': true}, 'c': []}]")]
        public void FindNamedItem_returns_item(string json)
        {
            var item = VaultParser.FindNamedItem(JArray.Parse(json), "blah");

            Assert.NotNull(item);
            Assert.Equal("blah", (string)item["i"]["n"]);
        }

        [Theory]
        [InlineData("[]")]
        [InlineData("[{'i': {}}]")]
        [InlineData("[{'i': {'n': null}}]")]
        [InlineData("[{'i': {'n': ''}}]")]
        [InlineData("[{'i': {'n': 'blah-blah'}}, {'i': {'n': 'blah-blah-blah'}}]")]
        public void FindNamedItem_returns_null(string json)
        {
            var item = VaultParser.FindNamedItem(JArray.Parse(json), "blah");
            Assert.Null(item);
        }

        //
        // Data
        //

        private const string TopLevelPrefix = "{'i': {'F': true}, 'c': [";
        private const string TopLevelSuffix = "]}";
        private const string RootPrefix = TopLevelPrefix + "{'i': {'F': true, 'n': 'root'}, 'c': [";
        private const string RootSuffix = "]}" + TopLevelSuffix;
        private const string RootNoContent = "{'i': {'F': true, 'n': 'root'}}";
    }
}
