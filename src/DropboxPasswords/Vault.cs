// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;

#nullable enable

namespace PasswordManagerAccess.DropboxPasswords
{
    // TODO: Move this out of here!
    public interface IUi
    {
        // Returns the redirect URL with the code. null if canceled or errored.
        string PerformOAuthLogin(string url, string redirectUrl);

        // Optional. Tell the user that the enrollment request has been sent to other enrolled devices.
        void EnrollRequestSent(string[] deviceNames);
    }

    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(ClientInfo clientInfo, IUi ui, ISecureStorage storage)
        {
            return Open(clientInfo, Array.Empty<string>(), ui, storage);
        }

        public static Vault Open(ClientInfo clientInfo, string[] recoveryWords, IUi ui, ISecureStorage storage)
        {
            using var transport = new RestTransport();
            return new Vault(Client.OpenVault(clientInfo, recoveryWords, ui, storage, transport));
        }

        public static string GenerateRandomDeviceId()
        {
            return Guid.NewGuid().ToString().ToUpper();
        }

        //
        // Internal
        //

        internal Vault(Account[] accounts)
        {
            Accounts = accounts;
        }
    }
}
