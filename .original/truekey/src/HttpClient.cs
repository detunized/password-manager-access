// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net;
using Newtonsoft.Json;

namespace TrueKey
{
    public class HttpClient: IHttpClient
    {
        public string Post(string url, Dictionary<string, string> parameters)
        {
            using (var client = new WebClient())
            {
                client.Headers[HttpRequestHeader.ContentType] = "application/json; charset=UTF-8";

                // TODO: Handle network errors
                return client.UploadString(url, JsonConvert.SerializeObject(parameters));
            }
        }
    }
}
