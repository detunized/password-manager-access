// Copyright (C) 2016 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;

namespace Dashlane
{
    public class Vault
    {
        public static Vault Open(string username, string password, string uki)
        {
            using (var webClient = new WebClient())
                return Open(username, password, username, webClient);
        }

        public static Vault Open(string username, string password, string uki, IWebClient webClient)
        {
            return new Vault(Fetcher.Fetch(username, uki, webClient), password);
        }

        public Account[] Accounts { get; private set; }

        private Vault(JObject blob, string password)
        {
            var accounts = new List<Account>();

            var fullFile = blob.GetString("fullBackupFile");
            if (!string.IsNullOrWhiteSpace(fullFile))
                accounts.AddRange(Parser.ExtractEncryptedAccounts(fullFile.Decode64(), password));

            Accounts = accounts.OrderBy(i => i.Id).ToArray();
        }
    }
}
