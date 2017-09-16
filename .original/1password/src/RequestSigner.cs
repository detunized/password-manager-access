// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;

namespace OnePassword
{
    internal class RequestSigner: IRequestSigner
    {
        public RequestSigner(Session session, AesKey sessionKey)
            : this(session, sessionKey, Crypto.RandonUInt32())
        {
        }

        public RequestSigner(Session session, AesKey sessionKey, uint seed)
        {
            _sessionId = session.Id;
            _salt = Crypto.CalculateSessionHmacSalt(sessionKey);
            _requestId = seed;
        }

        // This function has a non-obvious but intended side effect.
        // RequestId is bumped every time the message is signed. Thus
        // calling this function again on the same request would yield
        // a different result.
        public KeyValuePair<string, string> Sign(string url, string method)
        {
            var id = _requestId;
            _requestId += 1;

            var signature = CalculateAuthSignature(CalculateAuthMessage(url, method, id), id);
            return new KeyValuePair<string, string>("X-AgileBits-MAC", signature);
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
            var hash = Crypto.Hmac256(_salt, authMessage);
            var hash12 = hash.Take(12).ToArray().ToBase64();
            return string.Format("v1|{0}|{1}", requestId, hash12);
        }

        private readonly string _sessionId;
        private readonly byte[] _salt;
        private uint _requestId;
    }
}
