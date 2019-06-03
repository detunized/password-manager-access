// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using RestSharp;

namespace PasswordManagerAccess.ZohoVault
{
    public interface IWebClient
    {
        IRestResponse Get(string url, Dictionary<string, string> headers, Dictionary<string, string> cookies);

        IRestResponse Post(string url,
                           Dictionary<string, object> parameters,
                           Dictionary<string, string> headers,
                           Dictionary<string, string> cookies);
    }
}
