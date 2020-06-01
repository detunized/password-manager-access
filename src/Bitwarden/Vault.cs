// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Bitwarden.Ui;
using PasswordManagerAccess.Common;

namespace PasswordManagerAccess.Bitwarden
{
    public class Vault
    {
        public readonly Account[] Accounts;

        // Main entry point. Use this function to open the vault.
        // The device ID should be unique to each installation, but it should not be new on
        // every run. A new random device ID should be generated with GenerateRandomDeviceId
        // on the first run and reused later on.
        public static Vault Open(string username, string password, string deviceId, IUi ui, ISecureStorage storage)
        {
            return Open(username, password, deviceId, null, ui, storage);
        }

        // This version allows custom base URL. baseUrl could be set to null or "" for a default value.
        public static Vault Open(string username,
                                 string password,
                                 string deviceId,
                                 string baseUrl,
                                 IUi ui,
                                 ISecureStorage storage)
        {
            using var transport = new RestTransport();
            return new Vault(Client.OpenVault(username, password, deviceId, baseUrl, ui, storage, transport));
        }

        public static string GenerateRandomDeviceId()
        {
            return Guid.NewGuid().ToString();
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
