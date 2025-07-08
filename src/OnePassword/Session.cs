// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.OnePassword;

// The session object is opaque to the user. It holds all the state needed by Client to perform
// various operations like opening vaults or logging out.
public sealed class Session : IDisposable
{
    internal Credentials Credentials { get; }
    internal Keychain Keychain { get; }
    internal AesKey Key { get; }
    internal RestClient Rest { get; }
    private IRestTransport Transport { get; }

    internal Session(Credentials credentials, Keychain keychain, AesKey key, RestClient rest, IRestTransport transport)
    {
        Credentials = credentials;
        Keychain = keychain;
        Key = key;
        Rest = rest;
        Transport = transport;
    }

    public void Dispose() => Transport.Dispose();
}
