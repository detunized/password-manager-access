// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;

namespace PasswordManagerAccess.OnePassword
{
    internal interface IRequestSigner
    {
        KeyValuePair<string, string> Sign(string url, string method);
    }
}
