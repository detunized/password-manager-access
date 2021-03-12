// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.TrueKey
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string username, string password, Ui ui, ISecureStorage storage)
        {
            using var transport = new RestTransport();
            return Open(username, password, ui, storage, transport);
        }

        // TODO: Write a test that runs the whole sequence and checks the result.
        internal static Vault Open(string username,
                                   string password,
                                   Ui ui,
                                   ISecureStorage storage,
                                   IRestTransport transport)
        {
            return new Vault(Client.OpenVault(username, password, ui, storage, transport));
        }

        //
        // Private
        //

        private Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
