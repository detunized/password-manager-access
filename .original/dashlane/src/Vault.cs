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
                return Open(username, password, uki, webClient);
        }

        public static Vault Open(string username, string password, string uki, IWebClient webClient)
        {
            return new Vault(Remote.Fetch(username, uki, webClient), password);
        }

        public Account[] Accounts { get; private set; }

        private Vault(JObject blob, string password)
        {
            var accounts = new Dictionary<string, Account>();

            var fullFile = blob.GetString("fullBackupFile");
            if (!string.IsNullOrWhiteSpace(fullFile))
                foreach (var i in Parse.ExtractEncryptedAccounts(fullFile.Decode64(), password))
                    accounts.Add(i.Id, i);

            foreach (var transaction in blob.SelectToken("transactionList"))
            {
                if (transaction.GetString("type") != "AUTHENTIFIANT")
                    continue;

                switch (transaction.GetString("action"))
                {
                case "BACKUP_EDIT":
                    var content = transaction.GetString("content");
                    if (!string.IsNullOrWhiteSpace(content))
                        foreach (var i in Parse.ExtractEncryptedAccounts(content.Decode64(), password))
                            accounts.Add(i.Id, i);

                    break;
                case "BACKUP_REMOVE":
                    var id = transaction.GetString("identifier");
                    if (id != null)
                        accounts.Remove(id);

                    break;
                }
            }

            Accounts = accounts.Values.OrderBy(i => i.Id).ToArray();
        }
    }
}
