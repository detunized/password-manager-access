// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Net.Http;

namespace PasswordManagerAccess.RoboForm
{
    public interface IHttpClient
    {
        HttpResponseMessage Get(string url, Dictionary<string, string> headers);
        HttpResponseMessage Post(string url, Dictionary<string, string> headers);
    }
}
