// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Linq;
using Newtonsoft.Json;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ZohoVault
{
    using R = Response;

    public class Vault
    {
        public static Vault Open(string username, string password, string passphrase)
        {
            using (var rest = new RestClient())
                return Open(username, password, passphrase, rest);
        }

        internal static Vault Open(string username, string password, string passphrase, RestClient rest)
        {
            var token = Remote.Login(username, password, rest);
            try
            {
                var key = Remote.Authenticate(token, passphrase, rest);
                var vaultResponse = Remote.DownloadVault(token, rest);

                return Open(vaultResponse, key);
            }
            finally
            {
                Remote.Logout(token, rest);
            }
        }

        internal static Vault Open(R.Vault vaultResponse, byte[] key)
        {
            // TODO: Test on non account type secrets!
            // TODO: Test on accounts with missing fields!
            var accounts = vaultResponse.Secrets
                .Select(x => ParseAccount(x, key))
                .Where(x => x != null)
                .ToArray();

            return new Vault { Accounts = accounts };
        }

        // Returns null on accounts that don't parse
        internal static Account ParseAccount(R.Secret secret, byte[] key)
        {
            try
            {
                var data = JsonConvert.DeserializeObject<R.SecretData>(secret.Data);
                return new Account(
                        secret.Id,
                        secret.Name,
                        Crypto.DecryptString(data.Username, key),
                        Crypto.DecryptString(data.Password, key),
                        secret.Url,
                        Crypto.DecryptString(secret.Note, key));
            }
            catch (JsonException)
            {
                // If it doesn't parse then it's some other kind of unsupported secret type. Ignore.
                return null;
            }
        }

        public Account[] Accounts { get; private set; }
    }
}
