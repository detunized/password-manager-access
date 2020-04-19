// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.TrueKey
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string username, string password, Ui ui, ISecureStorage storage)
        {
            return Open(username, password, ui, storage, new HttpClient());
        }

        // TODO: Write a test that runs the whole sequence and checks the result.
        public static Vault Open(string username,
                                 string password,
                                 Ui ui,
                                 ISecureStorage storage,
                                 IHttpClient http)
        {
            return new Vault(Client.OpenVault(username, password, ui, storage, http));
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
