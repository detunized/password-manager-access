// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

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
                                 string deviceId = DefaultDeviceId,
                                 string deviceName = DefaultDeviceName)
        {
            // Request the token that is encrypted with the master password.
            var encryptedToken = Client.GetEncryptedToken(username, deviceId, DateTime.Now);

            // Decrypt the token. This token is now used to authenticate with the server.
            var token = Util.DecryptToken(username, password, encryptedToken);

            // The device must be registered first.
            Client.AuthorizeDevice(username, token, deviceId, deviceName, DateTime.Now);

            // Get the S3 credentials to access the database on AWS.
            var s3Token = Client.GetS3Token(username, token, deviceId, DateTime.Now);

            // Download the database.
            var db = Client.DownloadLatestDb(s3Token);

            // Parse the database, extract and decrypt all the account information.
            var accounts = Parser.ParseAccounts(db, password);

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
