// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OnePassword
{
    // TODO: Make internal
    public class JsonHttpClient
    {
        public JsonHttpClient(IHttpClient http, string baseUrl)
        {
            _http = http;
            _baseUrl = baseUrl.TrimEnd('/');
        }

        //
        // Get
        //

        public JObject Get(string endpoint)
        {
            return Get(endpoint, new Dictionary<string, string>());
        }

        public JObject Get(string endpoint, Dictionary<string, string> headers)
        {
            return JObject.Parse(_http.Get(MakeUrl(endpoint), headers));
        }

        public T Get<T>(string endpoint, Func<JObject, T> parse)
        {
            return Get(endpoint, new Dictionary<string, string>(), parse);
        }

        public T Get<T>(string endpoint,
                        Dictionary<string, string> headers,
                        Func<JObject, T> parse)
        {
            return parse(Get(endpoint, headers));
        }

        //
        // Post
        //

        public JObject Post(string endpoint, Dictionary<string, object> parameters)
        {
            return Post(endpoint, parameters, new Dictionary<string, string>());
        }

        public JObject Post(string endpoint,
                            Dictionary<string, object> parameters,
                            Dictionary<string, string> headers)
        {
            var jsonHeaders = new Dictionary<string, string>(headers);
            jsonHeaders["Content-Type"] = "application/json; charset=UTF-8";

            return JObject.Parse(_http.Post(MakeUrl(endpoint),
                                            JsonConvert.SerializeObject(parameters),
                                            jsonHeaders));
        }

        //
        // Private
        //

        internal string MakeUrl(string endpoint)
        {
            return _baseUrl + '/' + endpoint.TrimStart('/');
        }

        private readonly IHttpClient _http;
        private readonly string _baseUrl;
    }
}
