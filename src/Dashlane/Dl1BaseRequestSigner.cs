// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Text;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Dashlane;

internal abstract class Dl1BaseRequestSigner : IRequestSigner
{
    public IReadOnlyDictionary<string, string> Sign(Uri uri, HttpMethod method, IReadOnlyDictionary<string, string> headers, HttpContent content) =>
        Sign(uri, method, headers, content, Os.UnixSeconds());

    //
    // Protected
    //

    protected abstract string GetSigningKey();
    protected abstract string GetAuthIdentity();

    //
    // Internal
    //

    internal IReadOnlyDictionary<string, string> Sign(
        Uri uri,
        HttpMethod method,
        IReadOnlyDictionary<string, string> headers,
        HttpContent content,
        uint timestamp
    )
    {
        var headersToSign = FormatHeaderForSigning(headers, content);
        var headerOrder = headersToSign.Keys.OrderBy(x => x).ToArray();
        var request = BuildRequest(uri, method, headersToSign, headerOrder, content);
        var requestHashHex = Crypto.Sha256(request).ToHex();
        var signingMaterial = BuildAuthSigningMaterial(timestamp, requestHashHex);
        var signature = Crypto.HmacSha256(GetSigningKey().ToBytes(), signingMaterial).ToHex();
        var extraHeaders = new Dictionary<string, string> { ["Authorization"] = BuildAuthHeader(timestamp, headerOrder, signature) };

        return headers.Merge(extraHeaders);
    }

    internal string BuildAuthHeader(uint timestamp, string[] headerOrder, string signature)
    {
        var headers = headerOrder.JoinToString(";");
        var authId = GetAuthIdentity();
        return $"DL1-HMAC-SHA256 {authId},Timestamp={timestamp},SignedHeaders={headers},Signature={signature}";
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

    internal static string BuildAuthSigningMaterial(uint timestamp, string requestHash) => $"DL1-HMAC-SHA256\n{timestamp}\n{requestHash}";

    internal const string AppAccessKey = "HB9JQATDY6Y62JYKT7KXBN4C7FH8HKC5";
    internal const string AppAccessSecret = "boUtXxmDgLUtNFaigCMQ3+u+LAx0tg1ePAUE13nkR7dto+Zwq1naOHZTwbxxM7iL";

    internal static readonly HashSet<string> HeadersToSignLowerCase = ["content-type", "user-agent"];
}
