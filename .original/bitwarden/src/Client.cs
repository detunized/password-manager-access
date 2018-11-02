// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json;

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
            var response = jsonHttp.Post<KdfResponse>("api/accounts/prelogin",
                                                      new Dictionary<string, string> {{"email", username}});

            // TODO: Check Kdf field and throw if it's not the one we support.
            return response.KdfIterations;
        }

        //
        // Internal
        //

        // TODO: Move this out of here. Maybe?
        [JsonObject(ItemRequired = Required.Always)]
        internal struct KdfResponse
        {
            public int Kdf;
            public int KdfIterations;
        }
    }
}
