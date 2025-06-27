// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ProtonPass
{
    public record VaultInfo(string Id, string Name, string Description);

    public record Vault(VaultInfo Info, Account[] Accounts);
}
