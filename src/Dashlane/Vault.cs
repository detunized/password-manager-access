// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Dashlane
{
    using R = Response;

    public class Vault
    {
        public static Vault Open(string username, string password, Ui ui, ISecureStorage storage)
        {
            using var transport = new RestTransport();
            return Open(username, password, ui, storage, transport);
        }

        //
        // Internal
        //

        internal static Vault Open(string username, string password, Ui ui, ISecureStorage storage, IRestTransport transport)
        {
            return new Vault(ClientWeb.OpenVault(username, ui, storage, transport), password);
        }

        internal Vault(R.Vault blob, string password)
        {
            var accounts = new Dictionary<string, Account>();
            var keyCache = new Parse.DerivedKeyCache();

            // This is used with the MFA. The server supplies the password prefix that is used in encryption.
            var serverKey = blob.ServerKey ?? "";
            var fullPassword = serverKey + password;

            var fullFile = blob.EncryptedAccounts;
            if (!string.IsNullOrWhiteSpace(fullFile))
                foreach (var i in Parse.ExtractEncryptedAccounts(fullFile.Decode64(), fullPassword, keyCache))
                    accounts[i.Id] = i;

            foreach (var transaction in blob.Transactions ?? new R.Transaction[0])
            {
                if (transaction.Kind != "AUTHENTIFIANT")
                    continue;

                switch (transaction.Action)
                {
                case "BACKUP_EDIT":
                    var content = transaction.Content;
                    if (!string.IsNullOrWhiteSpace(content))
                        foreach (var i in Parse.ExtractEncryptedAccounts(content.Decode64(), fullPassword, keyCache))
                            accounts[i.Id] = i;

                    break;
                case "BACKUP_REMOVE":
                    var id = transaction.Id;
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
