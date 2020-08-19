// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword
{
    // TODO: Rename to Session
    /// The session object is opaque to the user. It hold all the state needed by Client to perform
    /// various operations like opening vaults or logging out.
    public class LoginSession
    {
        internal readonly ClientInfo ClientInfo;
        internal readonly Keychain Keychain;
        internal readonly AesKey Key;
        internal readonly RestClient Rest;
        internal readonly IRestTransport Transport;

        internal LoginSession(ClientInfo clientInfo,
                              Keychain keychain,
                              AesKey key,
                              RestClient rest,
                              IRestTransport transport)
        {
            ClientInfo = clientInfo;
            Keychain = keychain;
            Key = key;
            Rest = rest;
            Transport = transport;
        }
    }
}
