// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

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

            return Open(vaultJson, passphrase);
        }

        public static Vault Open(string json, string passphrase)
        {
            var j = JObject.Parse(json);
            var accounts = j["operation"]["details"]["SECRETS"].Select(i => (string)i["SECRETNAME"]).ToArray();
            return new Vault(accounts);
        }

        internal Vault(string[] accounts)
        {
            Accounts = accounts;
        }

        public string[] Accounts { get; private set; }
    }
}
