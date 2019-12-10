// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Net;

namespace OnePassword
{
    internal class MitmproxyHttpClient: HttpClient
    {
        private const string MitmproxyUrl = "http://10.0.2.2:8080";

        static MitmproxyHttpClient()
        {
            // Disable TLS certificate check for mitmproxy
            ServicePointManager.ServerCertificateValidationCallback = delegate { return true; };
        }

        //
        // Protected
        //

        protected override WebClient NewWebClient()
        {
            return new WebClient { Proxy = new WebProxy(new Uri(MitmproxyUrl), false) };
        }
    }
}
