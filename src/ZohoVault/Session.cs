// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ZohoVault
{
    public class Session
    {
        internal readonly Dictionary<string, string> Cookies;
        internal readonly string Domain;
        internal readonly RestClient Rest;
        internal readonly IRestTransport Transport;
        internal readonly Settings Settings;
        internal readonly ISecureStorage Storage;
        internal readonly byte[] VaultKey;

        internal Session(
            Dictionary<string, string> cookies,
            string domain,
            RestClient rest,
            IRestTransport transport,
            Settings settings,
            ISecureStorage storage,
            byte[] vaultKey
        )
        {
            Cookies = cookies;
            Domain = domain;
            Rest = rest;
            Transport = transport;
            Settings = settings;
            Storage = storage;
            VaultKey = vaultKey;
        }
    }
}
