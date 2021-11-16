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

        // The main entry point. Use this function to open the vault in the browser mode. In
        // this the login process is interactive when 2FA is enabled. This is an old mode
        // that might potentially trigger a captcha. Captcha solving is not supported.
        // There's no way to complete a login and get the vault if the captcha is triggered.
        // Use the CLI/API mode. This mode requires a different type of credentials.
        // The device ID should be unique to each installation, but it should not be new on
        // every run. A new random device ID should be generated with GenerateRandomDeviceId
        // on the first run and reused later on.
        public static Vault Open(ClientInfoBrowser clientInfo, IUi ui, ISecureStorage storage)
        {
            return Open(clientInfo, null, ui, storage);
        }

        // This version allows custom base URL. baseUrl could be set to null or "" for the default value.
        public static Vault Open(ClientInfoBrowser clientInfo, string baseUrl, IUi ui, ISecureStorage storage)
        {
            using var transport = new RestTransport();
            return new Vault(Client.OpenVaultBrowser(username: clientInfo.Username,
                                                     password: clientInfo.Password,
                                                     deviceId: clientInfo.DeviceId,
                                                     baseUrl: baseUrl,
                                                     ui: ui,
                                                     storage: storage,
                                                     transport: transport));
        }

        // The main entry point. Use this function to open the vault in the CLI/API mode. In
        // this mode the login is fully non-interactive even with 2FA enabled. Bitwarden servers
        // don't use 2FA in this mode and permit to bypass it. There's no captcha in this mode
        // either. If the browser mode is triggering a captcha, this mode should be used instead.
        // This mode requires a different type of credentials that could be found in the vault
        // settings: the client ID and the client secret.
        // The device ID should be unique to each installation, but it should not be new on
        // every run. A new random device ID should be generated with GenerateRandomDeviceId
        // on the first run and reused later on.
        public static Vault Open(ClientInfoCliApi clientInfo, string baseUrl = null)
        {
            using var transport = new RestTransport();
            return new Vault(Client.OpenVaultCliApi(clientId: clientInfo.ClientId,
                                                    clientSecret: clientInfo.ClientSecret,
                                                    password: clientInfo.Password,
                                                    deviceId: clientInfo.DeviceId,
                                                    baseUrl: baseUrl,
                                                    transport: transport));
        }

        [Obsolete("Please use the overloads with either ClientInfoBrowser or ClientInfoCliApi")]
        public static Vault Open(string username, string password, string deviceId, IUi ui, ISecureStorage storage)
        {
            return Open(username, password, deviceId, null, ui, storage);
        }

        [Obsolete("Please use the overloads with either ClientInfoBrowser or ClientInfoCliApi")]
        public static Vault Open(string username,
                                 string password,
                                 string deviceId,
                                 string baseUrl,
                                 IUi ui,
                                 ISecureStorage storage)
        {
            return Open(new ClientInfoBrowser(username: username,
                                              password: password,
                                              deviceId: deviceId),
                        baseUrl,
                        ui,
                        storage);
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
