// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.OnePassword.Response;

namespace PasswordManagerAccess.OnePassword
{
    /// The session object is opaque to the user. It holds all the state needed by Client to perform
    /// various operations like opening vaults or logging out.
    public class Session
    {
        internal readonly Credentials Credentials;
        internal readonly Keychain Keychain;
        internal readonly AesKey Key;
        internal readonly RestClient Rest;
        internal readonly IRestTransport Transport;

        // Cache
        internal R.AccountInfo? AccountInfo { get; set; }
        internal VaultInfo[]? AccessibleVaults { get; set; }

        internal Session(Credentials credentials, Keychain keychain, AesKey key, RestClient rest, IRestTransport transport)
        {
            Credentials = credentials;
            Keychain = keychain;
            Key = key;
            Rest = rest;
            Transport = transport;
        }
    }
}
