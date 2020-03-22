// // Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// // Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    // Generate a proper test case with AWS SDK
    public class S3Test
    {
        [Fact]
        public void GetObject_returns_bytes()
        {
            var flow = new RestFlow().Get("bytes");
            var result = S3.GetObject("bucket", "path", Credentials, DateTime.Now, flow);

            Assert.Equal("bytes", result.ToUtf8());
        }

        [Fact]
        public void MakeHeaders_returns_headers()
        {
            var headers = S3.MakeHeaders(Host, "path/to/object", Credentials, Timestamp);

            var names = headers.Keys;
            Assert.Equal(6, names.Count);
            Assert.Contains("Authorization", names);
            Assert.Contains("Host", names);
            Assert.Contains("User-Agent", names);
            Assert.Contains("X-Amz-Content-SHA256", names);
            Assert.Contains("X-Amz-Date", names);
            Assert.Contains("X-Amz-Security-Token", names);
        }

        [Fact]
        public void MakeAuthorizationHeader_returns_auth_header()
        {
            var header = S3.MakeAuthorizationHeader("blah", "blah-blah", Credentials);

            Assert.Contains($"Credential={Credentials.AccessKeyId}/blah", header);
            Assert.Contains("Signature=blah-blah", header);
            Assert.Contains("SignedHeaders=host;user-agent;x-amz-", header);
        }

        [Fact]
        public void MakeCanonicalRequestString_inserts_headers_into_result()
        {
            var headers = new Dictionary<string, string>()
            {
                ["Host"] = Host,
                ["User-Agent"] = "firefox",
                ["X-Amz-Content-SHA256"] = "deadbeef",
                ["X-Amz-Date"] = "today",
                ["X-Amz-Security-Token"] = "blah-blah",
            };
            var request = S3.MakeCanonicalRequestString(RootPath, headers);

            Assert.StartsWith("GET\n", request);
            Assert.Contains($"\n{RootPath}\n", request);

            foreach (var header in headers)
                Assert.Contains($"\n{header.Key.ToLowerInvariant()}:{header.Value}", request);

            // SHA256("")
            Assert.EndsWith("\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", request);
        }

        [Fact]
        public void MakeStringToSign_returns_string_to_sign()
        {
            var sts = S3.MakeStringToSign("blah", "today", "blah-blah");

            Assert.StartsWith("AWS4-HMAC-SHA256\n", sts);
            Assert.Contains("\ntoday\n", sts);
            Assert.Contains("\nblah\n", sts);

            // SHA256("blah-blah")
            Assert.EndsWith("\n0810b032040c0b17d2d3f8775494bc3c7a39e83a3e39757646e5e1d1cc97763d", sts);
        }

        [Fact]
        public void MakeSigningKey_returns_key()
        {
            var key = S3.MakeSigningKey("blah", Credentials);

            // TODO: Check the actual key
            Assert.Equal(32, key.Length);
        }

        //
        // Data
        //

        private const string Host = "host.s3.aws";
        private const string Path = "path/to/object";
        private const string RootPath = "/path/to/object";
        private const string UserAgent = "user-agent";

        private static readonly S3.Credentials Credentials = new S3.Credentials("access-key-id",
                                                                                "secret-access-key",
                                                                                "security-token");

        private static readonly DateTime Timestamp = new DateTime(2020, 12, 11);
    }
}
