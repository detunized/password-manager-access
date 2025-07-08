// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable
using System;
using System.Collections.Generic;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ProtonPass;

// The session object is opaque to the user. It holds all the state needed by Client to perform
// various operations like opening vaults or logging out.
public sealed class Session : IDisposable
{
    internal Model.UserKey PrimaryKey { get; }
    internal string KeyPassphrase { get; }
    internal RestClient Rest { get; }
    private IRestTransport Transport { get; }

    internal Dictionary<string, VaultInfo> VaultInfos { get; } = [];

    internal Session(Model.UserKey primaryKey, string keyPassphrase, RestClient rest, IRestTransport transport)
    {
        PrimaryKey = primaryKey;
        KeyPassphrase = keyPassphrase;
        Rest = rest;
        Transport = transport;
    }

    public void Dispose() => Transport.Dispose();
}
