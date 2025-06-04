// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ZohoVault
{
    // TODO: See what could be removed from here!
    public class Session
    {
        internal readonly Dictionary<string, string> Cookies;
        internal readonly string Token;
        internal readonly Client.UserInfo UserInfo;
        internal readonly RestClient Rest;
        internal readonly IRestTransport Transport;
        internal readonly Settings Settings;
        internal readonly ISecureStorage Storage;

        internal Session(
            Dictionary<string, string> cookies,
            string token,
            Client.UserInfo userInfo,
            RestClient rest,
            IRestTransport transport,
            Settings settings,
            ISecureStorage storage
        )
        {
            Cookies = cookies;
            Token = token;
            UserInfo = userInfo;
            Rest = rest;
            Transport = transport;
            Settings = settings;
            Storage = storage;
        }
    }
}
