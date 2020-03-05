// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;

namespace PasswordManagerAccess.StickyPassword
{
    // This is not intended to be a general purpose HTTP client. This interface intentionally
    // defines only the bare minimum of what is needed to communicate with the StickyPassword
    // server.
    public interface IHttpClient
    {
        string Post(string endpoint,
                    string userAgent,
                    DateTime timestamp,
                    Dictionary<string, string> parameters);

        string Post(string endpoint,
                    string userAgent,
                    string authorization,
                    DateTime timestamp,
                    Dictionary<string, string> parameters);
    }
}
