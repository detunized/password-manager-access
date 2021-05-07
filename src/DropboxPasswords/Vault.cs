// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

#nullable enable

namespace PasswordManagerAccess.DropboxPasswords
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string oauthToken, string[] recoveryWords)
        {
            using var transport = new RestTransport();
            return Open(oauthToken, recoveryWords, transport);
        }

        //
        // Internal
        //

        internal Vault(Account[] accounts)
        {
            Accounts = accounts;
        }

        internal static Vault Open(string oauthToken, string[] recoveryWords, IRestTransport transport)
        {
            return new Vault(Client.OpenVault(oauthToken, recoveryWords, transport));
        }
    }
}
