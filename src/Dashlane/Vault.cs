// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Dashlane
{
    using R = Response;

    public class Vault
    {
        public static Vault Open(string username, string password, string deviceId, Ui ui)
        {
            using (var transport = new RestTransport())
                return Open(username, password, deviceId, ui, transport);
        }

        public static string GenerateRandomDeviceId()
        {
            // Generates something like this:
            // 852dc12ff32a4fc0905e3ff0076868bf-92d3115e-9dae-4c70-a139-5b0063da4ed6
            return new[] {32, 8, 4, 4, 4, 12}
                .Select(Crypto.RandomHex)
                .JoinToString("-");
        }

        //
        // Internal
        //

        internal static Vault Open(string username, string password, string deviceId, Ui ui, IRestTransport transport)
        {
            return new Vault(Remote.OpenVault(username, deviceId, ui, transport), password);
        }

        internal Vault(R.Vault blob, string password)
        {
            var accounts = new Dictionary<string, Account>();

            // This is used with the MFA. The server supplies the password prefix that is used in encryption.
            var serverKey = blob.ServerKey ?? "";
            var fullPassword = serverKey + password;

            var fullFile = blob.EncryptedAccounts;
            if (!string.IsNullOrWhiteSpace(fullFile))
                foreach (var i in Parse.ExtractEncryptedAccounts(fullFile.Decode64(), fullPassword))
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
                        foreach (var i in Parse.ExtractEncryptedAccounts(content.Decode64(), fullPassword))
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
