// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;
using System.Xml.XPath;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Kaspersky;
using Xunit;

namespace PasswordManagerAccess.Test.Kaspersky
{
    public class ParserTest : TestBase
    {
        [Fact]
        public void ParseVault_parses_large_vault()
        {
            var items = Enumerable.Range(1, 2).SelectMany(i => GetDbItemsFromFixture($"large-vault-response-{i}")).ToArray();

            Assert.Equal(72, items.Length);

            var accounts = Parser.ParseVault(items, EncryptionKeyLargeVault).ToArray();

            // TODO: Verify account details
            Assert.Equal(13, accounts.Length);
        }

        [Fact]
        public void ParseVault_returns_accounts_for_version_8()
        {
            var accounts = Parser.ParseVault(GetDbItemsFromFixture("vault-version8-response"), EncryptionKeyVersion8).ToArray();

            // TODO: Verify account details
            Assert.Equal(5, accounts.Length);
        }

        [Fact]
        public void ParseVault_returns_accounts_for_version_9()
        {
            var accounts = Parser.ParseVault(GetDbItemsFromFixture("vault-version9-response"), EncryptionKeyVersion9).OrderBy(x => x.Name).ToArray();

            Assert.Equal(4, accounts.Length);

            //
            //  0
            //

            var a0 = accounts[0];
            Assert.Equal("Nested", a0.Name);
            Assert.Equal("nested.com", a0.Url);
            Assert.Equal("", a0.Notes);
            Assert.Equal("Top Level 2", a0.Folder);
            Assert.Empty(a0.Credentials);

            //
            // 1
            //

            var a1 = accounts[1];
            Assert.Equal("Web 1 login", a1.Name);
            Assert.Equal("web1.com", a1.Url);
            Assert.Equal("", a1.Notes);
            Assert.Equal("Top Level 1", a1.Folder);
            Assert.Single(a1.Credentials);

            var c10 = a1.Credentials[0];
            Assert.Equal("Login1", c10.Name);
            Assert.Equal("log", c10.Username);
            Assert.Equal("pwd", c10.Password);
            Assert.Equal("Blah", c10.Notes);

            //
            // 2
            //

            var a2 = accounts[2];
            Assert.Equal("Web multiple logins", a2.Name);
            Assert.Equal("web2.com", a2.Url);
            Assert.Equal("", a2.Notes);
            Assert.Equal("", a2.Folder);
            Assert.Equal(2, a2.Credentials.Length);

            var c2 = a2.Credentials.OrderBy(x => x.Name).ToArray();
            var c20 = c2[0];
            Assert.Equal("Log12", c20.Name);
            Assert.Equal("logg", c20.Username);
            Assert.Equal("pwd", c20.Password);
            Assert.Equal("Blah", c20.Notes);

            var c21 = c2[1];
            Assert.Equal("Log22", c21.Name);
            Assert.Equal("logh", c21.Username);
            Assert.Equal("pwd", c21.Password);
            Assert.Equal("Blah", c21.Notes);

            //
            // 3
            //

            var a3 = accounts[3];
            Assert.Equal("Web no login", a3.Name);
            Assert.Equal("web0.com", a3.Url);
            Assert.Equal("", a3.Notes);
            Assert.Equal("", a3.Folder);
            Assert.Empty(a3.Credentials);
        }

        //
        // Version 8
        //

        // TODO: Add version 8 tests

        //
        // Version 9
        //

        [Fact]
        public void DecryptBlobVersion9_returns_plaintext()
        {
            var plaintext = Parser.DecryptBlobVersion9(BlobVersion9, EncryptionKeyVersion9);

            Assert.StartsWith("{\"unique_id\":", plaintext);
        }

        [Theory]
        // The IV is not hashed, only the tag and the ciphertext
        [InlineData(20)] // Tag
        [InlineData(51)] // Tag
        [InlineData(52)] // Ciphertext
        [InlineData(100)] // Ciphertext
        public void DecryptBlobVersion9_throws_on_mismatched_tag(int index)
        {
            // Copy and tamper
            var blob = BlobVersion9.Sub(0, int.MaxValue);
            blob[index] ^= 1;

            Exceptions.AssertThrowsInternalError(() => Parser.DecryptBlobVersion9(blob, EncryptionKeyVersion9), "tag doesn't match");
        }

        //
        // Version 9.2
        //

        [Fact]
        public void ParseVault_returns_accounts_for_version_92()
        {
            var accounts = Parser.ParseVault(GetDbItemsFromFixture("vault-response"), EncryptionKeyVersion92).ToArray();
            // TODO: Verify account details
            Assert.Equal(10, accounts.Length);
        }

        [Fact]
        public void ParseItemVersion92_returns_fields()
        {
            var blob =
                "AwAAAHja7Vdbc6pIEP4vvOakRAXEU5WHGRiJERRUSMjWqS2EAUZuyjWa8r8fyG5ysoZUadXZWmsr88Clp7/u5usZpvuZs"
                + "vI8Jasixxn1/Y9nyrFyi/r+TK3CZPUicAkOnba5Ljtkej2aZXp9nv1G5bsNroWHb1RsRfVTo42VxCG1AYc6fDuGu1aY4V"
                + "dY7xeMZCLepNiu0W2wPC3aUSi2093mTJBBMrIKcQuEbvmiEqcZSWLq8ONNFP1pJ1GE4/zFxIVx9TnsvyLLwa5VhLmceCT"
                + "+YuwUxryCOF9MncIUsZOvNXUaUxko8sSyc1JaOfli7VTWRlaZpCTH/x++Pkf9FsIkHOO0CXjayC6QtYurJuILJerytuPG"
                + "SuuyS0qTYiNd6Bl5caurSMMvnk7jCWw24W7ZaDczf8HYX7BNmmxwmhOcKTi3Xtyc6e/f3pm+lYm1opDE+Wt7ciKBMrFxn"
                + "J2d4BCfmSjQFCD4LC+LXWz7aRKT/Xmu3uPekvrpLqBoEbE000XXiOHRNUP32GvID9G1KNC9LgBDBAcs9eqIPrSV68cW/x"
                + "7XLZfX0W6x7T/324x/6MeOLEdppMwCj5b9K9XwOCGeaygfjB9mIVm6D3dw2N2P5YWapcqDVQbJfYDiUrGQat3Kt0wU6QW"
                + "zlKaTcr3eFgQ+zhn+cRw42s3NWzT9Q9vh988o4iIMW/Xft95HgRMDzuYVPZG8BNRjutB9pHv1E2xegSYAs7m7fGfov0ge"
                + "pos5PQZpxtic1gjmsaZ3a23haV2VvKnpjfDORv6jXQEgZkr9OhCB7ZRbqQEI+kKfQ0P0VfMKbiw3VAXLKoCdDjvuEJqqf"
                + "BfsyISXpAzWIZExnflVptqe2uuvyr7a66SGr005SEpgo9QIINvpdFxXVaQ9cu5FfoxKE8w0YPrcDm3FWdofmLNJECEwQb"
                + "QHuPFUk00DBgIk2wr7t8jywBPIyd1AmEdrCYjCYjd0vGgrAqny10z1JALoB1IfsR7OoC+o9x2mmQM4YaVZCcUXXlA4Wga"
                + "LQosEoT1pb23XUQZmrJnQoy2ZF9vAXctKWATG4H7EArFm0ZNCutjzworIcFcsO7DiSpX0VQ7uc/So9HtjnjdZp2QLYc9B"
                + "g1T9ACTTTliJc0GQsBKb3K292ju23zUG2ifL6fW0OwpsrpZOJrGok0yJP7EKcxLoOpRHm2UVZRF0ASsNLdm7c+HUNhB0X"
                + "S4okkCccWNVSW93+ZWv6xwS781tOpIfB7qzZhZ5dfN5EO+OkpN/dR/ajdNhH4vu07HHfeGPw0+s9YS/";

            var fields = Parser.ParseItemVersion92(
                blob.Decode64(),
                EncryptionKeyVersion92,
                new[] { "m_url", "m_name", "m_guid", "m_comment", "not valid" }
            );

            Assert.Equal(
                new Dictionary<string, string>
                {
                    ["m_url"] = "bing.com",
                    ["m_name"] = "Bing",
                    ["m_comment"] = "",
                    ["m_guid"] = "0DE5041E-E48E-4025-B89E-DC021AA9EB75",
                },
                fields
            );
        }

        [Fact]
        public void DecryptBlobVersion92_decrypts_blob()
        {
            var blob = BlobIv.Concat(BlobTag).Concat(BlobCiphertext).ToArray();
            var plaintext = Parser.DecryptBlobVersion92(blob, EncryptionKeyVersion92);

            Assert.Equal(BlobPlaintext, plaintext);
        }

        [Theory]
        // The IV is not hashed, only the tag and the ciphertext
        [InlineData(16)] // Tag
        [InlineData(47)] // Tag
        [InlineData(48)] // Ciphertext
        [InlineData(79)] // Ciphertext
        public void DecryptBlobVersion92_throws_on_mismatched_tag(int index)
        {
            // Copy and tamper
            var blob = BlobIv.Concat(BlobTag).Concat(BlobCiphertext).ToArray();
            blob[index] ^= 1;

            Exceptions.AssertThrowsInternalError(() => Parser.DecryptBlobVersion92(blob, EncryptionKeyVersion92), "tag doesn't match");
        }

        //
        // Helpers
        //

        internal IEnumerable<Bosh.Change> GetDbItemsFromFixture(string name)
        {
            return XDocument
                .Parse(GetFixture(name, "xml"))
                .XPathSelectElements("//*[starts-with(local-name(), 'item_')]")
                .Select(x => new Bosh.Change(
                    x.Attribute("id").Value,
                    Bosh.ParseOperation(x.Attribute("unique_id").Value).Value,
                    x.Attribute("type")?.Value ?? "",
                    x.Attribute("dataInBase64")?.Value ?? ""
                ));
        }

        //
        // Data
        //

        internal static readonly byte[] EncryptionKeyLargeVault = "b7ae681b5946f23c33f14cefef0b4361dc348ad5a0f40ea9503adfba0d2bbe34".DecodeHex();

        internal static readonly byte[] EncryptionKeyVersion8 = "0741524aefb42058143123852073ad326c4e9e0eba2afcd850b04e34a553ae90".DecodeHex();

        internal static readonly byte[] EncryptionKeyVersion9 = "8469d3c56a1b0a85ea047186376356469aea716eb55b5866aca55c0f98a310ad".DecodeHex();

        internal static readonly byte[] EncryptionKeyVersion92 = "d8f2bfe4980d90e3d402844e5332859ecbda531ab24962d2fdad4d39ad98d2f9".DecodeHex();

        internal static readonly byte[] BlobIv = "3b9628d05aa246eaa47e32cc96e915ed".DecodeHex();

        internal static readonly byte[] BlobTag = "61790030097201a5d2ecfc09b88b072b93fc1c3abcf8b73fa073b4464cdf623c".DecodeHex();

        internal static readonly byte[] BlobCiphertext = "f18e5dbf9b82cfa0558b0de402837f9700d108219e32763a1dc6f375c87557b4".DecodeHex();

        internal const string BlobPlaintext = "bing.com";

        internal const string BlobVersion9Base64 =
            "AgAAAHM6i/oLFfNORsx1WOxBXiyGFFAtScvAX30J7GQVCKsG4qiQtMdimyHfiIPgmbrEJymydKP6Urmt6DjQJEUfe6MifbqO/W3V+9v8"
            + "0dj5t6iEEcnDXwnmIOIanRvrFWIg24/mdO1MP4xXjD8kTvEkD3frd40Ms/Z9tXhad9veE8j4/QnPpM4JR5P2T2T4HDkRVub8E4WERmL4"
            + "hB29vquuH3u7GGUJk3bDQF9RaqwCE6/OeNZsPOZrQPCeLbn28mNWeUeaGElvcW3QVpTUTSLAV63D2oaF+Xzq5NTzsA4BWTlzuAyJftws"
            + "gQ29s6jqPub4QoN3TsQZJ/qZbgFyvUhLhWWq1V+GJBVpnjEYmuzLprdmKEMqJRnSoC8xxCuh8FDWdGUxm+LD8EgeHSikOKffontdbmpi"
            + "KBFujxtd0pcRlV6U9aq+aP13qjuYfVoQjP5sso2tVc5SFIO8SniqvdQDYnY=";

        internal static readonly byte[] BlobVersion9 = BlobVersion9Base64.Decode64();
    }
}
