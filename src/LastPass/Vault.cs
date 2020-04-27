// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Security.Cryptography;

namespace PasswordManagerAccess.LastPass
{
    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string username, string password, ClientInfo clientInfo, Ui ui)
        {
            return new Vault(Client.OpenVault(username, password, clientInfo, ui));
        }

        public static string GenerateRandomClientId()
        {
            using (var random = new RNGCryptoServiceProvider())
            {
                var bytes = new byte[16];
                random.GetBytes(bytes);
                return bytes.ToHex();
            }
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
