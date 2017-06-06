// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace OnePassword
{
    internal class Client
    {
        public Client(IHttpClient http)
        {
            _http = new JsonHttpClient(http);
        }

        public Remote.Session StartNewSession(Remote.ClientInfo clientInfo)
        {
            var response = _http.Get(new[] {"auth", clientInfo.Username, clientInfo.Uuid, "-"});
            var status = response["status"].ToString();
            switch (status)
            {
            case "ok":
                return new Remote.Session(response["sessionID"].ToString());
            default:
                // TODO: Use custom exception
                throw new InvalidOperationException(
                    string.Format(
                        "Failed to start a new session, unsupported response status '{0}'",
                        status));
            }
        }

        //
        // Private
        //

        private readonly JsonHttpClient _http;
    }
}
