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
    internal class Dl1RequestSigner : IRequestSigner
    {
        // TODO: Rework this!
        public string Username { get; init; } = "";
        public string Uki { get; init; } = "";

        public IReadOnlyDictionary<string, string> Sign(Uri uri, HttpMethod method, IReadOnlyDictionary<string, string> headers, HttpContent content)
        {
            return Sign(uri, method, headers, content, Os.UnixSeconds(), Username, Uki);
        }

        //
        // Internal
        //

        internal static IReadOnlyDictionary<string, string> Sign(
            Uri uri,
            HttpMethod method,
            IReadOnlyDictionary<string, string> headers,
            HttpContent content,
            uint timestamp,
            string username = "",
            string uki = ""
        )
        {
            var headersToSign = FormatHeaderForSigning(headers, content);
            var headerOrder = headersToSign.Keys.OrderBy(x => x).ToArray();
            var request = BuildRequest(uri, method, headersToSign, headerOrder, content);
            var requestHashHex = Crypto.Sha256(request).ToHex();
            var signingMaterial = BuildAuthSigningMaterial(timestamp, requestHashHex);
            var key = uki.IsNullOrEmpty() ? AppAccessSecret : $"{AppAccessSecret}\n{uki.Split('-')[1]}";
            var signature = Crypto.HmacSha256(key.ToBytes(), signingMaterial).ToHex();
            var extraHeaders = new Dictionary<string, string>
            {
                ["Authorization"] = BuildAuthHeader(timestamp, headerOrder, signature, username, uki),
            };

            return headers.Merge(extraHeaders);
        }

        internal static string BuildAuthHeader(uint timestamp, string[] headerOrder, string signature, string username = "", string uki = "")
        {
            var headers = headerOrder.JoinToString(";");
            var login = username.IsNullOrEmpty() ? "" : $"Login={username},";
            var device = uki.IsNullOrEmpty() ? "" : $"DeviceAccessKey={uki.Split('-')[0]},";
            return $"DL1-HMAC-SHA256 {login}AppAccessKey={AppAccessKey},{device}Timestamp={timestamp},SignedHeaders={headers},Signature={signature}";
        }

        internal static string HashBody(HttpContent content)
        {
            var body = content.ReadAsStringAsync().GetAwaiter().GetResult();
            return Crypto.Sha256(body).ToHex();
        }

        internal static Dictionary<string, string> FormatHeaderForSigning(IReadOnlyDictionary<string, string> headers, HttpContent content)
        {
            var formattedHeaders = new Dictionary<string, string>();

            foreach (var kv in headers)
            {
                var name = kv.Key.ToLower();
                if (!HeadersToSignLowerCase.Contains(name))
                    continue;

                formattedHeaders[name] = kv.Value;
            }

            foreach (var kv in content.Headers)
            {
                var name = kv.Key.ToLower();
                if (!HeadersToSignLowerCase.Contains(name))
                    continue;

                formattedHeaders[name] = kv.Value.JoinToString(", ");
            }

            return formattedHeaders;
        }

        internal static string BuildRequest(
            Uri uri,
            HttpMethod method,
            Dictionary<string, string> headersToSign,
            string[] headerOrder,
            HttpContent content
        )
        {
            var request = new StringBuilder();
            request.AppendLineLf(method.ToString());
            request.AppendLineLf(uri.AbsolutePath);
            request.AppendLineLf("");
            foreach (var name in headerOrder)
                request.AppendLineLf($"{name}:{headersToSign[name]}");
            request.AppendLineLf("");
            request.AppendLineLf(headerOrder.JoinToString(";"));

            // The last line should not have the trailing '\n'!
            request.Append(HashBody(content));

            return request.ToString();
        }

        internal static string BuildAuthSigningMaterial(uint timestamp, string requestHash)
        {
            return $"DL1-HMAC-SHA256\n{timestamp}\n{requestHash}";
        }

        private const string AppAccessKey = "HB9JQATDY6Y62JYKT7KXBN4C7FH8HKC5";
        private static readonly string AppAccessSecret = "boUtXxmDgLUtNFaigCMQ3+u+LAx0tg1ePAUE13nkR7dto+Zwq1naOHZTwbxxM7iL";

        private static readonly HashSet<string> HeadersToSignLowerCase = ["content-type", "user-agent"];
    }
}
