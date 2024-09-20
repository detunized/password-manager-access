// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;

namespace PasswordManagerAccess.Common
{
    internal static class S3
    {
        public class Credentials
        {
            public readonly string AccessKeyId;
            public readonly string SecretAccessKey;
            public readonly string SecurityToken;

            public Credentials(string accessKeyId, string secretAccessKey, string securityToken)
            {
                AccessKeyId = accessKeyId;
                SecretAccessKey = secretAccessKey;
                SecurityToken = securityToken;
            }
        }

        // Downloads an object from S3 in us-east-1 region.
        public static byte[] GetObject(string bucket, string path, Credentials credentials, IRestTransport transport)
        {
            return GetObject(bucket, path, credentials, new RestClient(transport));
        }

        public static byte[] GetObject(string bucket, string path, Credentials credentials, RestClient rest)
        {
            return GetObject(bucket, path, credentials, DateTime.UtcNow, rest);
        }

        //
        // Internal
        //

        internal static byte[] GetObject(string bucket, string path, Credentials credentials, DateTime timestamp, RestClient rest)
        {
            var host = $"{bucket}.s3.amazonaws.com";
            var rootPath = path.StartsWith("/") ? path : '/' + path;
            var headers = MakeHeaders(host, rootPath, credentials, timestamp);

            var response = rest.GetBinary($"https://{host}{rootPath}", headers);
            if (response.IsSuccessful)
                return response.Content;

            throw new InternalErrorException("Failed to get an S3 object", response.Error);
        }

        internal static Dictionary<string, string> MakeHeaders(string host, string rootPath, Credentials credentials, DateTime timestamp)
        {
            var timestampUtc = timestamp.ToUniversalTime();
            var dateIso8601 = timestampUtc.ToString("yyyyMMdd");
            var timestampIso8601 = timestampUtc.ToString("yyyyMMddTHHmmssZ");

            var scope = $"{dateIso8601}/{Region}/s3/aws4_request";

            var headers = new Dictionary<string, string>(6)
            {
                ["Host"] = host,
                ["User-Agent"] = UserAgent,
                ["X-Amz-Content-SHA256"] = Sha256OfBlank,
                ["X-Amz-Date"] = timestampIso8601,
                ["X-Amz-Security-Token"] = credentials.SecurityToken,
            };

            var canonicalRequest = MakeCanonicalRequestString(rootPath, headers);
            var stringToSign = MakeStringToSign(scope, timestampIso8601, canonicalRequest);
            var key = MakeSigningKey(scope, credentials);
            var signature = Crypto.HmacSha256(key, stringToSign).ToHex();

            // This header is not signed
            headers["Authorization"] = MakeAuthorizationHeader(scope, signature, credentials);

            return headers;
        }

        internal static string MakeAuthorizationHeader(string scope, string signature, Credentials credentials)
        {
            return $"AWS4-HMAC-SHA256 Credential={credentials.AccessKeyId}/{scope}, SignedHeaders={SignedHeaders}, Signature={signature}";
        }

        internal static string MakeCanonicalRequestString(string rootPath, Dictionary<string, string> headers)
        {
            return new[]
            {
                "GET",
                rootPath,
                "",
                // Change this if/whe the set of headers change!
                "host:" + headers["Host"],
                "user-agent:" + headers["User-Agent"],
                "x-amz-content-sha256:" + headers["X-Amz-Content-SHA256"],
                "x-amz-date:" + headers["X-Amz-Date"],
                "x-amz-security-token:" + headers["X-Amz-Security-Token"],
                "",
                SignedHeaders,
                Sha256OfBlank,
            }.JoinToString("\n");
        }

        internal static string MakeStringToSign(string scope, string timestamp, string canonicalRequest)
        {
            return new[] { "AWS4-HMAC-SHA256", timestamp, scope, Crypto.Sha256(canonicalRequest).ToHex() }.JoinToString("\n");
        }

        internal static byte[] MakeSigningKey(string scope, Credentials credentials)
        {
            var key = $"AWS4{credentials.SecretAccessKey}".ToBytes();
            foreach (var step in scope.Split('/'))
                key = Crypto.HmacSha256(key, step);

            return key;
        }

        //
        // Private
        //

        private const string Region = "us-east-1";
        private const string UserAgent =
            "aws-sdk-dotnet-45/3.3.110.30 aws-sdk-dotnet-core/3.3.104.32 .NET_Runtime/4.0 .NET_Framework/4.0 OS/Microsoft_Windows_NT_6.2.9200.0 ClientAsync";

        // SHA256("")
        private const string Sha256OfBlank = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

        // This should be synchronized with headers in the functions above. It's pre-baked not generate this on every request.
        private const string SignedHeaders = "host;user-agent;x-amz-content-sha256;x-amz-date;x-amz-security-token";
    }
}
