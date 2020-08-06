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
    public class ParserTest: TestBase
    {
        [Fact]
        public void ParseVault_returns_accounts()
        {
            var changes = XDocument.Parse(GetFixture("vault-response", "xml"))
                .XPathSelectElements("//*[starts-with(local-name(), 'item_')]")
                .Select(x => new Bosh.Change(x.Attribute("type").Value, x.Attribute("dataInBase64").Value));

            var accounts = Parser.ParseVault(changes, EncryptionKey).ToArray();

            Assert.Equal(10, accounts.Length);
        }

        [Fact]
        public void ParseItemVersion92_returns_fields()
        {
            var blob = "AwAAAHja7Vdbc6pIEP4vvOakRAXEU5WHGRiJERRUSMjWqS2EAUZuyjWa8r8fyG5ysoZUadXZWmsr88Clp7/u5usZpvuZs" +
                       "vI8Jasixxn1/Y9nyrFyi/r+TK3CZPUicAkOnba5Ljtkej2aZXp9nv1G5bsNroWHb1RsRfVTo42VxCG1AYc6fDuGu1aY4V" +
                       "dY7xeMZCLepNiu0W2wPC3aUSi2093mTJBBMrIKcQuEbvmiEqcZSWLq8ONNFP1pJ1GE4/zFxIVx9TnsvyLLwa5VhLmceCT" +
                       "+YuwUxryCOF9MncIUsZOvNXUaUxko8sSyc1JaOfli7VTWRlaZpCTH/x++Pkf9FsIkHOO0CXjayC6QtYurJuILJerytuPG" +
                       "SuuyS0qTYiNd6Bl5caurSMMvnk7jCWw24W7ZaDczf8HYX7BNmmxwmhOcKTi3Xtyc6e/f3pm+lYm1opDE+Wt7ciKBMrFxn" +
                       "J2d4BCfmSjQFCD4LC+LXWz7aRKT/Xmu3uPekvrpLqBoEbE000XXiOHRNUP32GvID9G1KNC9LgBDBAcs9eqIPrSV68cW/x" +
                       "7XLZfX0W6x7T/324x/6MeOLEdppMwCj5b9K9XwOCGeaygfjB9mIVm6D3dw2N2P5YWapcqDVQbJfYDiUrGQat3Kt0wU6QW" +
                       "zlKaTcr3eFgQ+zhn+cRw42s3NWzT9Q9vh988o4iIMW/Xft95HgRMDzuYVPZG8BNRjutB9pHv1E2xegSYAs7m7fGfov0ge" +
                       "pos5PQZpxtic1gjmsaZ3a23haV2VvKnpjfDORv6jXQEgZkr9OhCB7ZRbqQEI+kKfQ0P0VfMKbiw3VAXLKoCdDjvuEJqqf" +
                       "BfsyISXpAzWIZExnflVptqe2uuvyr7a66SGr005SEpgo9QIINvpdFxXVaQ9cu5FfoxKE8w0YPrcDm3FWdofmLNJECEwQb" +
                       "QHuPFUk00DBgIk2wr7t8jywBPIyd1AmEdrCYjCYjd0vGgrAqny10z1JALoB1IfsR7OoC+o9x2mmQM4YaVZCcUXXlA4Wga" +
                       "LQosEoT1pb23XUQZmrJnQoy2ZF9vAXctKWATG4H7EArFm0ZNCutjzworIcFcsO7DiSpX0VQ7uc/So9HtjnjdZp2QLYc9B" +
                       "g1T9ACTTTliJc0GQsBKb3K292ju23zUG2ifL6fW0OwpsrpZOJrGok0yJP7EKcxLoOpRHm2UVZRF0ASsNLdm7c+HUNhB0X" +
                       "S4okkCccWNVSW93+ZWv6xwS781tOpIfB7qzZhZ5dfN5EO+OkpN/dR/ajdNhH4vu07HHfeGPw0+s9YS/";

            var fields = Parser.ParseItemVersion92(blob.Decode64(),
                                                   EncryptionKey,
                                                   new[] {"m_url", "m_name", "m_guid", "m_comment", "not valid"});

            Assert.Equal(new Dictionary<string, string>
                         {
                             ["m_url"] = "bing.com",
                             ["m_name"] = "Bing",
                             ["m_comment"] = "",
                             ["m_guid"] = "0DE5041E-E48E-4025-B89E-DC021AA9EB75",
                         },
                         fields);
        }

        [Fact]
        public void DecryptBlobVersion92_decrypts_blob()
        {
            var blob = BlobIv.Concat(BlobTag).Concat(BlobCiphertext).ToArray();
            var plaintext = Parser.DecryptBlobVersion92(blob, EncryptionKey);

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

            Exceptions.AssertThrowsInternalError(() => Parser.DecryptBlobVersion92(blob, EncryptionKey),
                                                 "tag doesn't match");
        }

        //
        // Data
        //

        internal static readonly byte[] EncryptionKey =
            "d8f2bfe4980d90e3d402844e5332859ecbda531ab24962d2fdad4d39ad98d2f9".DecodeHex();

        internal static readonly byte[] BlobIv = "3b9628d05aa246eaa47e32cc96e915ed".DecodeHex();

        internal static readonly byte[] BlobTag =
            "61790030097201a5d2ecfc09b88b072b93fc1c3abcf8b73fa073b4464cdf623c".DecodeHex();

        internal static readonly byte[] BlobCiphertext =
            "f18e5dbf9b82cfa0558b0de402837f9700d108219e32763a1dc6f375c87557b4".DecodeHex();

        internal const string BlobPlaintext = "bing.com";
    }
}
