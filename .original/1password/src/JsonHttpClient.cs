// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace OnePassword
{
    internal class JsonHttpClient
    {
        public JsonHttpClient(IHttpClient http, string baseUrl)
        {
            _http = http;
            _baseUrl = baseUrl.TrimEnd('/');

            Headers = new Dictionary<string, string>();
        }

        public Dictionary<string, string> Headers { get; set; }

        //
        // Get
        //

        public JObject Get(string endpoint)
        {
            return JObject.Parse(_http.Get(MakeUrl(endpoint), Headers));
        }

        public T Get<T>(string endpoint, Func<JObject, T> parse)
        {
            return parse(Get(endpoint));
        }

        //
        // Post
        //

        public JObject Post(string endpoint, Dictionary<string, object> parameters)
        {
            var jsonHeaders = new Dictionary<string, string>(Headers);
            jsonHeaders["Content-Type"] = "application/json; charset=UTF-8";

            return JObject.Parse(_http.Post(MakeUrl(endpoint),
                                            JsonConvert.SerializeObject(parameters),
                                            jsonHeaders));
        }

        //
        // Put
        //

        public JObject Put(string endpoint)
        {
            return JObject.Parse(_http.Put(MakeUrl(endpoint), Headers));
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
