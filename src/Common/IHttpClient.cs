// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace PasswordManagerAccess.Common
{
    public interface IHttpClient
    {
        // System.Net.WebException is expected to be thrown on errors
        string Get(string url, Dictionary<string, string> headers);
        string Post(string url, string content, Dictionary<string, string> headers);
    }
}
