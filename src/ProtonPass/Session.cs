// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable
using System;
using System.Collections.Generic;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ProtonPass;

public sealed class Session : IDisposable
{
    internal Model.UserKey PrimaryKey { get; }
    internal string KeyPassphrase { get; }
    internal RestClient Rest { get; }
    internal IRestTransport Transport { get; }

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
