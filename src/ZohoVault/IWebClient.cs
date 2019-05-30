// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Specialized;
using System.Net;

namespace PasswordManagerAccess.ZohoVault
{
    public interface IWebClient
    {
        byte[] UploadValues(string address, NameValueCollection data);
        byte[] DownloadData(string address);
        WebHeaderCollection Headers { get; }
        WebHeaderCollection ResponseHeaders { get; }
    }
}
