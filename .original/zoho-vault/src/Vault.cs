// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace ZohoVault
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
            var key = Remote.Authenticate(token, passphrase, webClient);
            var vaultJson = Remote.DownloadVault(token, key, webClient);

            return Open(vaultJson, key);
        }

        public static Vault Open(JToken json, byte[] key)
        {
            try
            {
                var accounts = json["SECRETS"].Select(entry =>
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
                });

                return new Vault { Accounts = accounts.ToArray() };
            }
            catch (ArgumentException e)
            {
                throw new ParseException(ParseException.FailureReason.InvalidFormat, "Invalid vault format", e);
            }
        }

        public Account[] Accounts { get; private set; }
    }
}
