// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

namespace PasswordManagerAccess.OnePassword
{
    public record Vault(VaultInfo Info, Account[] Accounts, SshKey[] SshKeys);
}
