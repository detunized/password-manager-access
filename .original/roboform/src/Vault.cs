// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

namespace RoboForm
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string username, string password, Ui ui)
        {
            return Open(username, password, ui, new HttpClient());
        }

        //
        // Internal
        //

        internal static Vault Open(string username, string password, Ui ui, IHttpClient http)
        {
            return Client.OpenVault(username, password, ui, http);
        }

        internal Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
