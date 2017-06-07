// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace OnePassword
{
    internal class Client
    {
        public const string ApiUrl = "https://my.1password.com/api/v1";

        public Client(IHttpClient http)
        {
            _http = new JsonHttpClient(http, ApiUrl);
        }

        public Session StartNewSession(ClientInfo clientInfo)
        {
            var endpoint = string.Join("/", "auth", clientInfo.Username, clientInfo.Uuid, "-");
            var response = _http.Get(endpoint);
            var status = response["status"].ToString();
            switch (status)
            {
            case "ok":
                return new Session(response["sessionID"].ToString());
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
