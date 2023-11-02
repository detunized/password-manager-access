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
    }

    public class Vault
    {
        public readonly Account[] Accounts;

        public static Vault Open(string oauthToken, string[] recoveryWords)
        {
            using var transport = new RestTransport();
            return Open(oauthToken, recoveryWords, transport);
        }

        public static Vault Open(string deviceId, IUi ui, ISecureStorage storage)
        {
            using var transport = new RestTransport();
            return new Vault(Client.OpenVault(deviceId, ui, storage, transport));
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

        internal static Vault Open(string oauthToken, string[] recoveryWords, IRestTransport transport)
        {
            return new Vault(Client.OpenVault(oauthToken, recoveryWords, transport));
        }
    }
}
