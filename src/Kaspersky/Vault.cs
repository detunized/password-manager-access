// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Kaspersky
{
    public class Vault
    {
        public static Vault Open(string username, string accountPassword, string vaultPassword)
        {
            using var transport = new RestTransport();
            return Open(username, accountPassword, vaultPassword, transport);
        }

        //
        // Internal
        //

        internal static Vault Open(string username,
                                   string accountPassword,
                                   string vaultPassword,
                                   IRestTransport transport)
        {
            Client.OpenVault(username, accountPassword, vaultPassword, transport);
            return new Vault();
        }
    }
}
