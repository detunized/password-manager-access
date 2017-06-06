// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using Newtonsoft.Json.Linq;

namespace OnePassword
{
    public class JsonHttpClient
    {
        public JsonHttpClient(IHttpClient http)
        {
            _http = http;
        }

        public JObject Get(string url, Dictionary<string, string> headers)
        {
            return JObject.Parse(_http.Get(url, headers));
        }

        private readonly IHttpClient _http;
    }
}
