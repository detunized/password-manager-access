// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.ZohoVault
{
    public class Vault
    {
        public static Vault Open(string username, string password, string passphrase)
        {
            using (var webClient = new WebClient())
                return Open(username, password, passphrase, webClient);
        }

        public static Vault Open(string username, string password, string passphrase, IWebClient webClient)
        {
            var token = Remote.Login(username, password, webClient);
            try
            {
                var key = Remote.Authenticate(token, passphrase, webClient);
                var vaultJson = Remote.DownloadVault(token, key, webClient);

                return Open(vaultJson, key);
            }
            finally
            {
                Remote.Logout(token, webClient);
            }
        }

        public static Vault Open(JToken json, byte[] key)
        {
            var accounts = json["SECRETS"]
                .Select(entry =>
                {
                    try
                    {
                        var secret = JObject.Parse(entry.StringAt("SECRETDATA"));
                        var username = Crypto.Decrypt(secret.StringAt("username").Decode64(), key).ToUtf8();
                        var password = Crypto.Decrypt(secret.StringAt("password").Decode64(), key).ToUtf8();
                        var note = Crypto.Decrypt(entry.StringAt("SECURENOTE").Decode64(), key).ToUtf8();

                        return new Account(
                            entry.StringAt("SECRETID"),
                            entry.StringAt("SECRETNAME"),
                            username,
                            password,
                            entry.StringAt("SECRETURL"),
                            note);
                    }
                    catch (ArgumentException)
                    {
                        // Some secret types don't look like accounts, so we simply ignore everything that doesn't parse
                        return null;
                    }
                })
                .Where(account => account != null);

            return new Vault {Accounts = accounts.ToArray()};
        }

        public Account[] Accounts { get; private set; }
    }
}
