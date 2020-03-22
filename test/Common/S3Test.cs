// // Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// // Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using PasswordManagerAccess.Common;
using Xunit;

namespace PasswordManagerAccess.Test.Common
{
    public class S3Test
    {
        [Fact]
        public void GetObject_returns_bytes()
        {
            var flow = new RestFlow().Get("bytes");
            var result = S3.GetObject("bucket", "path", Credentials, Timestamp, flow);

            Assert.Equal("bytes", result.ToUtf8());
        }

        [Fact]
        public void MakeHeaders_returns_correct_headers()
        {
            var headers = S3.MakeHeaders(Host, RootPath, Credentials, Timestamp);

            var names = headers.Keys;
            Assert.Equal(6, names.Count);
            Assert.Contains("Authorization", names);
            Assert.Contains("Host", names);
            Assert.Contains("User-Agent", names);
            Assert.Contains("X-Amz-Content-SHA256", names);
            Assert.Contains("X-Amz-Date", names);
            Assert.Contains("X-Amz-Security-Token", names);

            // Generated with AWS SDK
            Assert.Equal("AWS4-HMAC-SHA256 Credential=ASIASIFWL2FI3L4O3POJ/20200322/us-east-1/s3/aws4_request, Signed" +
                         "Headers=host;user-agent;x-amz-content-sha256;x-amz-date;x-amz-security-token, Signature=15c" +
                         "71697075d159912e92afd149cc537ef2ded3f1421c315010ae8e4c03c4031",
                         headers["Authorization"]);

            Assert.Equal(Host, headers["Host"]);

            Assert.Equal("aws-sdk-dotnet-45/3.3.110.30 aws-sdk-dotnet-core/3.3.104.32 .NET_Runtime/4.0 .NET_Framework" +
                         "/4.0 OS/Microsoft_Windows_NT_6.2.9200.0 ClientAsync",
                         headers["User-Agent"]);

            Assert.Equal("20200322T131438Z", headers["X-Amz-Date"]);

            Assert.Equal("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                         headers["X-Amz-Content-SHA256"]);

            Assert.Equal(Credentials.SecurityToken, headers["X-Amz-Security-Token"]);
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

        private const string Bucket = "spclouddata";
        private const string Host = Bucket + ".s3.amazonaws.com";
        private const string Path = "d31cc798-93cc-426b-b561-96590622720e/1/spc.info";
        private const string RootPath = "/" + Path;

        private static readonly S3.Credentials Credentials = new S3.Credentials(
            accessKeyId: "ASIASIFWL2FI3L4O3POJ",
            secretAccessKey: "yEODc90fX8vxx2XMrzjhlyggzk+HeVQn13r9UBnZ",
            securityToken: "FwoGZXIvYXdzEBYaDBS3n1KkrWqWp560CCLbAvdGQLio1lrrl1y9VQlopjJY15iHRIRGxFNPZDj8Yy8qiKiGKtPE2" +
                           "BoYOxxSxexcFcEKPnT4Xtyrwe80SCEIei2NYhszAd4UO/EIUY+Kffm/y4zktCnMScAoTP1jPOZcwoNxCSFVrBj5gn" +
                           "A6QH10Q6GXy1QUObVfH8nnAhbFN1iV+tsKgK374hRBGxG/duswF+nZRRa4h8PL+NcfxLpHG26rytXi/IerWswxm36" +
                           "uxc0PiIGtortVjsOIX0+Lc9ey/EH85a+QQOJeGe6ks0ML74EKS3uyWhQKGjsk9o8H23UvkW1Wq9qT3NnlGIgqMmbT" +
                           "jtEmPhswtQkv6DPgKRViSPfi15nIG43zGKaht6Bk9agbrlESd7/jnYgdg016OMyNJybPbTXjegm6hlxqEoTC1vH8Y" +
                           "tKCfwBYPD9HP3rhBAwdaZiJ98soG7st5l87rOaC7VNh/jMATliG9gHtKJ3m0vMFMilLyonsMTJnLGRleziy2lZOGH" +
                           "ONkB22MEw8haKj441yH3MCbEKxV+GHZg==");

        // X-Amz-Date: 20200322T131438Z
        private static readonly DateTime Timestamp = new DateTime(2020, 03, 22, 13, 14, 38, DateTimeKind.Utc);
    }
}
