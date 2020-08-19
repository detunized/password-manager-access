// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
{
    internal class MacRequestSigner: IRequestSigner
    {
        public MacRequestSigner(AesKey sessionKey): this(sessionKey, Crypto.RandomUInt32())
        {
        }

        public MacRequestSigner(AesKey sessionKey, uint seed)
        {
            _sessionId = sessionKey.Id;
            _salt = Util.CalculateSessionHmacSalt(sessionKey);
            _requestId = seed;
        }

        // This function has a non-obvious but intended side effect.
        // RequestId is bumped every time the message is signed. Thus
        // calling this function again on the same request would yield
        // a different result.
        public IReadOnlyDictionary<string, string> Sign(Uri uri,
                                                        HttpMethod method,
                                                        IReadOnlyDictionary<string, string> headers)
        {
            var id = _requestId;
            _requestId += 1;

            var signature = CalculateAuthSignature(CalculateAuthMessage(uri.ToString(), method.ToString(), id), id);
            return headers.Merge(new Dictionary<string, string> { { "X-AgileBits-MAC", signature } });
        }

        //
        // Private
        //

        internal string CalculateAuthMessage(string url, string method, uint requestId)
        {
            var uri = new Uri(url);
            return string.Format("{0}|{1}|{2}/{3}?{4}|v1|{5}",
                                 _sessionId,
                                 method.ToUpperInvariant(),
                                 uri.Host,
                                 uri.AbsolutePath.TrimStart('/'),
                                 uri.Query.TrimStart('?'),
                                 requestId);
        }

        internal string CalculateAuthSignature(string authMessage, uint requestId)
        {
            var hash = Crypto.HmacSha256(authMessage, _salt);
            var hash12 = hash.Take(12).ToArray().ToUrlSafeBase64NoPadding();
            return $"v1|{requestId}|{hash12}";
        }

        private readonly string _sessionId;
        private readonly byte[] _salt;
        private uint _requestId;
    }
}
