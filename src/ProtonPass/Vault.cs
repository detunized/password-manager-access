// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

namespace PasswordManagerAccess.ProtonPass
{
    public record VaultInfo(string Id, string Name, string Description)
    {
        internal byte[] VaultKey { get; init; } = [];
    }

    public record Vault(VaultInfo Info, Account[] Accounts);
}
