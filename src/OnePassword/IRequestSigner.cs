// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace OnePassword
{
    internal interface IRequestSigner
    {
        KeyValuePair<string, string> Sign(string url, string method);
    }
}
