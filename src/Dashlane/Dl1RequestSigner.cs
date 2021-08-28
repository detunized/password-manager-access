// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Dashlane
{
    // This request signer is used in the new Web protocol that is not fully supported yet.
    // The new web protocol doesn't seem to be fully implemented by Dashlane. They fall back
    // to ws1.dashlane.com calls all the time. Some features are not supported by the
    // web/extension clients. It's been put on ice for now.
    internal class Dl1RequestSigner: IRequestSigner
    {
        public IReadOnlyDictionary<string, string> Sign(Uri uri,
                                                        HttpMethod method,
                                                        IReadOnlyDictionary<string, string> headers,
                                                        HttpContent content)
        {
            var headersToSign = FormatHeaderForSigning(headers, content);
            var headerOrder = headersToSign.Keys.OrderBy(x => x).ToArray();
            var request = BuildRequest(uri, method, headersToSign, headerOrder, content);
            var requestHashHex = Crypto.Sha256(request).ToHex();
            var timestamp = Os.UnixSeconds();
            var signingMaterial = BuildAuthSigningMaterial(timestamp, requestHashHex);
            var signature = Crypto.HmacSha256(AppAccessSecret, signingMaterial).ToHex();
            var extraHeaders = new Dictionary<string, string>
            {
                ["Authorization"] = BuildAuthHeader(timestamp, headerOrder, signature),
            };

            return headers.Merge(extraHeaders);
        }

        internal static string BuildAuthHeader(uint timestamp, string[] headerOrder, string signature)
        {
            var headers = headerOrder.JoinToString(";");
            return $"DL1-HMAC-SHA256 AppAccessKey={AppAccessKey},Timestamp={timestamp},SignedHeaders={headers},Signature={signature}";
        }

        internal static string HashBody(HttpContent content)
        {
            var body = content.ReadAsStringAsync().GetAwaiter().GetResult();
            return Crypto.Sha256(body).ToHex();
        }

        internal static Dictionary<string, string> FormatHeaderForSigning(IReadOnlyDictionary<string, string> headers,
                                                                          HttpContent content)
        {
            var formattedHeaders = new Dictionary<string, string>();

            foreach (var kv in headers)
            {
                var name = kv.Key.ToLower();
                if (ExcludeHeadersLowerCase.Contains(name))
                    continue;

                formattedHeaders[name] = kv.Value;
            }

            foreach (var kv in content.Headers)
            {
                var name = kv.Key.ToLower();
                if (ExcludeHeadersLowerCase.Contains(name))
                    continue;

                formattedHeaders[name] = kv.Value.JoinToString(", ");
            }

            return formattedHeaders;
        }

        internal static string BuildRequest(Uri uri,
                                            HttpMethod method,
                                            Dictionary<string, string> headersToSign,
                                            string[] headerOrder,
                                            HttpContent content)
        {
            var request = new StringBuilder();
            request.AppendLine(method.ToString());
            request.AppendLine(uri.AbsolutePath);
            request.AppendLine("");
            foreach (var name in headerOrder)
                request.AppendLine($"{name}:{headersToSign[name]}");
            request.AppendLine("");
            request.AppendLine(headerOrder.JoinToString(";"));

            // The last line should not have the trailing '\n'!
            request.Append(HashBody(content));

            return request.ToString();
        }

        internal static string BuildAuthSigningMaterial(uint timestamp, string requestHash)
        {
            return $"DL1-HMAC-SHA256\n{timestamp}\n{requestHash}";
        }

        private const string AppAccessKey = "C4F8H4SEAMXNBQVSASVBWDDZNCVTESMY";
        private static readonly byte[] AppAccessSecret = "Na9Dz3WcmjMZ5pdYU1AmC5TdYkeWAOzvOK6PkbU4QjfjPQTSaXY8pjPwrvHfVH14".ToBytes();

        private static readonly HashSet<string> ExcludeHeadersLowerCase = new HashSet<string>
        {
            "content-length",
            "user-agent",
        };
    }
}
