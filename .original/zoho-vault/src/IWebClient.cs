// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Specialized;

namespace ZohoVault
{
    public interface IWebClient
    {
        byte[] UploadValues(string address, NameValueCollection data);
    }
}
