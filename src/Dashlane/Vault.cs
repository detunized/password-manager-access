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
        public static Vault Open(string username, string password, string deviceId, Ui ui)
        {
            using (var transport = new RestTransport())
                return Open(username, password, deviceId, ui, transport);
        }

        //
        // Internal
        //

        internal static Vault Open(string username, string password, string deviceId, Ui ui, IRestTransport transport)
        {
            return new Vault(Remote.OpenVault(username, deviceId, ui, transport), password);
        }

        internal Vault(JObject blob, string password)
        {
            var accounts = new Dictionary<string, Account>();

            // This is used with the MFA. The server supplies the password prefix that is used in encryption.
            var serverKey = blob.GetString("serverKey") ?? "";
            var fullPassword = serverKey + password;

            var fullFile = blob.GetString("fullBackupFile");
            if (!string.IsNullOrWhiteSpace(fullFile))
                foreach (var i in Parse.ExtractEncryptedAccounts(fullFile.Decode64(), fullPassword))
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
                        foreach (var i in Parse.ExtractEncryptedAccounts(content.Decode64(), fullPassword))
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
