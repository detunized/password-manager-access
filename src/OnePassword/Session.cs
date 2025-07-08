// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword;

/// The session object is opaque to the user. It holds all the state needed by Client to perform
/// various operations like opening vaults or logging out.
public class Session
{
    internal readonly Credentials Credentials;
    internal readonly Keychain Keychain;
    internal readonly AesKey Key;
    internal readonly RestClient Rest;
    internal readonly IRestTransport Transport;

    internal Session(Credentials credentials, Keychain keychain, AesKey key, RestClient rest, IRestTransport transport)
    {
        Credentials = credentials;
        Keychain = keychain;
        Key = key;
        Rest = rest;
        Transport = transport;
    }
}
