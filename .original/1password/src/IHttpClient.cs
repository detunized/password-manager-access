// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace OnePassword
{
    public interface IHttpClient
    {
        // System.Net.WebException is expected to be thrown on errors
        string Get(string url, Dictionary<string, string> headers);
        string Post(string url, string content, Dictionary<string, string> headers);
        string Put(string url, Dictionary<string, string> headers);
    }
}
