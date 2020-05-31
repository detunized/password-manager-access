// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.
using System.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.StickyPassword.Ui;

namespace PasswordManagerAccess.StickyPassword
{
    public sealed class Vault
    {
        public Account[] Accounts { get; }

        // The deviceId should be generated via Vault.GenerateRandomDeviceId on the first call and reused
        // later on for the same device. This allows to bypass the email verification on every connection and
        // prevents the pollution of the server side list of known devices.
        public static Vault Open(string username,
                                 string password,
                                 string deviceId,
                                 string deviceName,
                                 IUi ui,
                                 ISqliteProvider sqliteProvider)
        {
            // Download the database.
            using var transport = new RestTransport();
            var db = Client.OpenVaultDb(username: username,
                                        password: password,
                                        deviceId: deviceId,
                                        deviceName: deviceName,
                                        ui: ui,
                                        transport: transport);

            // Parse the database, extract and decrypt all the account information.
            var accounts = Parser.ParseAccounts(db, password, sqliteProvider);

            return new Vault(accounts);
        }

        public static string GenerateRandomDeviceId()
        {
            return new [] {8, 4, 4, 4, 12}.Select(Crypto.RandomHex).JoinToString("-");
        }

        //
        // Private
        //

        private Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
