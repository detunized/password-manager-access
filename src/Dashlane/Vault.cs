// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using Newtonsoft.Json.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Dashlane
{
    public class Vault
    {
        public static Vault Open(string username, string password, string uki)
        {
            using (var transport = new RestTransport())
                return Open(username, password, uki, transport);
        }

        // TODO: Change this to the UI pattern
        public static void RegisterUkiStep1(string username)
        {
            using (var webClient = new WebClient())
                Remote.RegisterUkiStep1(username, webClient);
        }

        // TODO: Change this to the UI pattern
        public static void RegisterUkiStep2(string username, string deviceName, string uki, string token)
        {
            using (var webClient = new WebClient())
                Remote.RegisterUkiStep2(username, deviceName, uki, token, webClient);
        }


        //
        // Internal
        //

        internal static Vault Open(string username, string password, string uki, IRestTransport transport)
        {
            return new Vault(Remote.Fetch(username, uki, transport), password);
        }

        internal Vault(JObject blob, string password)
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

        public Account[] Accounts { get; private set; }
    }
}
