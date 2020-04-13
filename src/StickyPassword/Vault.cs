// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.StickyPassword
{
    public sealed class Vault
    {
        // TODO: Get rid of this?
        public const string DefaultDeviceId = "4ee845e4-0ee9-a7e9-ca24-63c02571c132";
        public const string DefaultDeviceName = "stickypassword-sharp";

        public Account[] Accounts { get; }

        public static Vault Open(string username,
                                 string password,
                                 ISqliteProvider sqliteProvider,
                                 string deviceId = DefaultDeviceId,
                                 string deviceName = DefaultDeviceName)
        {
            // Download the database.
            using var transport = new RestTransport();
            var db = Client.OpenVaultDb(username: username,
                                        password: password,
                                        deviceId: deviceId,
                                        deviceName: deviceName,
                                        transport: transport);

            // Parse the database, extract and decrypt all the account information.
            var accounts = Parser.ParseAccounts(db, password, sqliteProvider);

            return new Vault(accounts);
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
