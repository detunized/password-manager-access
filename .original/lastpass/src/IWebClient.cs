// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Specialized;
using System.Net;

namespace LastPass
{
    public interface IWebClient
    {
        byte[] UploadValues(string address, NameValueCollection data);
        byte[] DownloadData(string address);
        WebHeaderCollection Headers { get; }
    }
}