// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace PasswordManagerAccess.NordPass;

public class Vault
{
    public Account[] Accounts { get; }

    public static Vault Open(string username, string password)
    {
        // TODO: Implement
        return new Vault([]);
    }

    //
    // Private
    //

    private Vault(Account[] accounts)
    {
        Accounts = accounts;
    }
}
