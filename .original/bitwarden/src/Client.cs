// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace Bitwarden
{
    public static class Client
    {
        public static int RequestKdfIterationCount(string username, IHttpClient http)
        {
            return RequestKdfIterationCount(username, new JsonHttpClient(http, "https://vault.bitwarden.com"));
        }

        internal static int RequestKdfIterationCount(string username, JsonHttpClient jsonHttp)
        {
            var response = jsonHttp.Post("api/accounts/prelogin",
                                         new Dictionary<string, string> {{"email", username}});

            return (int)response["KdfIterations"];
        }
    }
}
