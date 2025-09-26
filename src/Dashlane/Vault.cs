// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Common;
using R = PasswordManagerAccess.Dashlane.Response;

namespace PasswordManagerAccess.Dashlane
{
    public class Vault
    {
        public Account[] Accounts { get; }
        public ParseError[] ParseErrors { get; }

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
            var (vault, serverKey) = Client.OpenVault(username, ui, storage, transport);
            return new Vault(vault, serverKey, password);
        }

        // TODO: Move to Client?
        internal Vault(R.Vault blob, string serverKey, string password)
        {
            var accounts = new Dictionary<string, Account>();
            var parseErrors = new List<ParseError>();
            var keyCache = new Parse.DerivedKeyCache();

            // This is used with the MFA. The server supplies the password prefix that is used in encryption.
            var fullPassword = serverKey + password;

            foreach (var transaction in blob.Transactions)
            {
                // This is a special transaction that can be decrypted to test if the master password is correct
                if (transaction.Id == "SETTINGS_userId" && transaction.Kind == "SETTINGS" && transaction.Action == "BACKUP_EDIT")
                {
                    try
                    {
                        // Decrypt and ignore the result
                        Parse.DecryptBlob(transaction.Content.Decode64(), fullPassword, keyCache);
                    }
                    catch (BadCredentialsException)
                    {
                        throw new BadCredentialsException("The password is incorrect");
                    }
                }

                switch (transaction.Action)
                {
                    case "BACKUP_EDIT":
                        var content = transaction.Content;
                        if (!string.IsNullOrWhiteSpace(content))
                        {
                            try
                            {
                                foreach (var i in Parse.ExtractEncryptedAccounts(content.Decode64(), fullPassword, keyCache))
                                    accounts[i.Id] = i;
                            }
                            catch (BadCredentialsException e)
                            {
                                parseErrors.Add(
                                    new ParseError(
                                        $"Failed to decrypt a vault item '{transaction.Id}' of type '{transaction.Action}'",
                                        e.Message,
                                        e.StackTrace
                                    )
                                );
                            }
                        }

                        break;
                    case "BACKUP_REMOVE":
                        var id = transaction.Id;
                        if (id != null)
                            accounts.Remove(id);

                        break;
                }
            }

            Accounts = accounts.Values.OrderBy(i => i.Id).ToArray();
            ParseErrors = [];
        }
    }
}
