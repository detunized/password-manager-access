// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;

namespace StickyPassword
{
    public class Vault
    {
        public const string DefaultDeviceId = "4ee845e4-0ee9-a7e9-ca24-63c02571c132";
        public const string DefaultDeviceName = "stickypassword-sharp";

        public static Vault Open(string username,
                                 string password,
                                 string deviceId = DefaultDeviceId,
                                 string deviceName = DefaultDeviceName)
        {
            var encryptedToken = Remote.GetEncryptedToken(username, deviceId, DateTime.Now);
            var token = Crypto.DecryptToken(username, password, encryptedToken);
            Remote.AuthorizeDevice(username, token, deviceId, deviceName, DateTime.Now);
            var s3Token = Remote.GetS3Token(username, token, deviceId, DateTime.Now);
            var db = Remote.DownloadLastestDb(s3Token);
            var accounts = Parser.ParseAccounts(db, password);

            return new Vault(accounts);
        }

        private Vault(Account[] accounts)
        {
            Accounts = accounts;
        }

        public Account[] Accounts { get; private set; }
    }
}
