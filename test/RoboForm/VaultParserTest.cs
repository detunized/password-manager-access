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
        public void Parse_returns_vault(string fixture)
        {
            var vault = VaultParser.Parse(JObject.Parse(GetFixture(fixture)));
            Assert.True(vault.Accounts.Length > 1);
        }

        [Theory]
        // Root with no content
        [InlineData("{'i': {'F': true}, 'c': [{'i': {'F': true, 'n': 'root'}}]}")]
        // Root with empty content
        [InlineData(RootPrefix + RootSuffix)]
        // Root with a folder but no accounts
        [InlineData(RootPrefix + "{'i': {'F': true, 'n': 'blah'}}" + RootSuffix)]
        public void Parse_returns_empty_vault(string json)
        {
            var vault = VaultParser.Parse(JObject.Parse(json));
            Assert.Empty(vault.Accounts);
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

        private const string RootPrefix = "{'i': {'F': true}, 'c': [{'i': {'F': true, 'n': 'root'}, 'c': [";
        private const string RootSuffix = "]}]}";
    }
}
