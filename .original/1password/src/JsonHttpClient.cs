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
            Http = http;
            BaseUrl = baseUrl.TrimEnd('/');
            Headers = new Dictionary<string, string>();
        }

        public IHttpClient Http { get; private set; }
        public string BaseUrl { get; private set; }
        public Dictionary<string, string> Headers { get; set; }

        //
        // Get
        //

        public JObject Get(string endpoint)
        {
            return JObject.Parse(Http.Get(MakeUrl(endpoint), Headers));
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

            return JObject.Parse(Http.Post(MakeUrl(endpoint),
                                            JsonConvert.SerializeObject(parameters),
                                            jsonHeaders));
        }

        //
        // Put
        //

        public JObject Put(string endpoint)
        {
            return JObject.Parse(Http.Put(MakeUrl(endpoint), Headers));
        }

        //
        // Private
        //

        internal string MakeUrl(string endpoint)
        {
            return BaseUrl + '/' + endpoint.TrimStart('/');
        }
    }
}
