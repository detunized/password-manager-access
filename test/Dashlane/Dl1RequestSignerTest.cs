// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Net.Http;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Dashlane;
using Xunit;

namespace PasswordManagerAccess.Test.Dashlane
{
    public class Dl1RequestSignerTest
    {
        [Fact]
        public void Sign_returns_headers()
        {
            var headers = Dl1RequestSigner.Sign(new Uri("https://blah.blah"),
                                                HttpMethod.Post,
                                                new Dictionary<string, string>
                                                {
                                                    ["name1"] = "value1",
                                                    ["name2"] = "value2",
                                                    ["name3"] = "value3",
                                                    ["User-Agent"] = "Browser",
                                                    ["Content-Length"] = "1337",
                                                },
                                                MakeHttpContent(),
                                                1234567890);

            var expected = new Dictionary<string, string>
            {
                ["name1"] = "value1",
                ["name2"] = "value2",
                ["name3"] = "value3",
                ["User-Agent"] = "Browser",
                ["Content-Length"] = "1337",
                ["Authorization"] = "DL1-HMAC-SHA256 AppAccessKey=C4F8H4SEAMXNBQVSASVBWDDZNCVTESMY,Timestamp=1234567890,SignedHeaders=content-header-name;content-type;ignored-content-header-name;name1;name2;name3,Signature=c68d0658fe6707d0cbedafe24e6a845460ddb7e98baf1236815ed40ae30052ee",
            };
            
            Assert.Equal(expected, headers);
        }

        [Fact]
        public void BuildAuthHeader_returns_header()
        {
            var header = Dl1RequestSigner.BuildAuthHeader(1234567890, new[] { "h1", "h2", "h3" }, "deadbeef");
            var expected = "DL1-HMAC-SHA256 AppAccessKey=C4F8H4SEAMXNBQVSASVBWDDZNCVTESMY,Timestamp=1234567890,SignedHeaders=h1;h2;h3,Signature=deadbeef";
            
            Assert.Equal(expected, header);
        }

        [Fact]
        public void HashBody_return_body_hash()
        {
            var hash = Dl1RequestSigner.HashBody(MakeHttpContent());
            Assert.Equal(ContentSha256, hash);
        }

        [Fact]
        public void FormatHeaderForSigning_returns_headers()
        {
            var content = new ByteArrayContent("".ToBytes());
            content.Headers.Add("Content-Length", "1337");
            content.Headers.Add("Content-Header", "content-header-value1");
            content.Headers.Add("Content-Header", "content-header-value2");

            var headers = Dl1RequestSigner.FormatHeaderForSigning(new Dictionary<string, string>
                                                                  {
                                                                      ["name1"] = "value1",
                                                                      ["name2"] = "value2",
                                                                      ["name3"] = "value3",
                                                                      ["User-Agent"] = "Browser",
                                                                      ["Content-Length"] = "1337",
                                                                  },
                                                                  content);

            var expected = new Dictionary<string, string>
            {
                ["name1"] = "value1",
                ["name2"] = "value2",
                ["name3"] = "value3",
                ["content-header"] = "content-header-value1, content-header-value2",
            };
            
            Assert.Equal(expected, headers);
        }

        [Fact]
        public void BuildRequest_returns_request_string()
        {
            var r = Dl1RequestSigner.BuildRequest(new Uri("https://blah.blah"),
                                                  HttpMethod.Post,
                                                  new Dictionary<string, string>
                                                  {
                                                      ["name3"] = "value3",
                                                      ["ignored2"] = "ignored2",
                                                      ["name2"] = "value2",
                                                      ["ignored1"] = "ignored1",
                                                      ["name1"] = "value1",
                                                  },
                                                  new[] { "name1", "name2", "name3" },
                                                  MakeHttpContent());

            var expected = new[]
            {
                "POST",
                "/",
                "",
                "name1:value1",
                "name2:value2",
                "name3:value3",
                "",
                "name1;name2;name3",
                ContentSha256
            }.JoinToString("\n");
            
            Assert.Equal(expected, r);
        }

        [Fact]
        public void BuildAuthSigningMaterial_returns_signing_material()
        {
            var material = Dl1RequestSigner.BuildAuthSigningMaterial(1234567890, "deadbeef");
            Assert.Equal("DL1-HMAC-SHA256\n1234567890\ndeadbeef", material);
        }
        
        //
        // Helpers
        //

        internal static HttpContent MakeHttpContent()
        {
            var content = new StringContent("string-content-line1\nstring-content-line2");
            content.Headers.Add("content-header-name", "content-header-value");
            content.Headers.Add("ignored-content-header-name", "ignored-content-header-value");
            return content;
        }

        //
        // Data
        //

        private const uint Timestamp = 1234567890;
        private const string ContentSha256 = "121daa986d8b8ef61459c322035929d9b14724cff672b88a9b8fc4ccf5787965";
        private const string RequestHash = "deadbeef";
    }
}