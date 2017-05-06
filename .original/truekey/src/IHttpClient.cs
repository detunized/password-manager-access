// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace TrueKey
{
    public interface IHttpClient
    {
        string Get(string url, Dictionary<string, string> headers);
        string Post(string url, Dictionary<string, object> parameters, Dictionary<string, string> headers);
    }
}
