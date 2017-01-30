// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;

namespace StickyPassword
{
    public interface IHttpClient
    {
        string Post(string url,
                    string userAgent,
                    DateTime timestamp,
                    Dictionary<string, string> parameters);

        string Post(string url,
                    string userAgent,
                    string authorization,
                    DateTime timestamp,
                    Dictionary<string, string> parameters);
    }
}
