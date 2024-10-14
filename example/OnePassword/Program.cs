// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.OnePassword;
using PasswordManagerAccess.OnePassword.Ui;

namespace Example
{
    public static class Program
    {
        private class TextUi : DuoUi, IUi
        {
            public Passcode ProvideGoogleAuthPasscode()
            {
                var passcode = GetAnswer($"Enter Google Authenticator passcode {PressEnterToCancel}");
                return string.IsNullOrWhiteSpace(passcode) ? Passcode.Cancel : new Passcode(passcode, GetRememberMe());
            }

            public Passcode ProvideWebAuthnRememberMe()
            {
                var yesNo = GetAnswer($"Remember this device? {PressEnterToCancel}").ToLower();
                return string.IsNullOrWhiteSpace(yesNo) ? Passcode.Cancel : new Passcode("", yesNo == "y" || yesNo == "yes");
            }
        }

        public static void Main()
        {
            // Read 1Password credentials from a file
            // The file should contain 5 values:
            //   - username
            //   - password
            //   - account key
            //   - client UUID or device ID
            //   - API domain (my.1password.com, my.1password.eu or my.1password.ca)
            // See config.yaml.example for an example.
            var config = Util.ReadConfig();

            string serviceAccountToken;
            config.TryGetValue("service-account-token", out serviceAccountToken);

            try
            {
                DumpAllVaults(
                    config["username"],
                    config["password"],
                    config["account-key"],
                    config["domain"],
                    config["device-id"],
                    serviceAccountToken ?? ""
                );
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }

        private static void DumpAllVaults(string username, string password, string accountKey, string domain, string uuid, string serviceAccountToken)
        {
            var device = new AppInfo { Name = "PMA 1Password example", Version = "1.0.0" };

            var session = string.IsNullOrEmpty(serviceAccountToken)
                ? Client.LogIn(
                    new Credentials
                    {
                        Username = username,
                        Password = password,
                        AccountKey = accountKey,
                        Domain = domain,
                        DeviceUuid = uuid,
                    },
                    device,
                    new TextUi(),
                    new PlainStorage()
                )
                : Client.LogIn(new ServiceAccount { Token = serviceAccountToken }, device);

            try
            {
                var vaults = Client.ListAllVaults(session);

                for (var i = 0; i < vaults.Length; i++)
                    DumpVault(i, vaults[i], session);
            }
            finally
            {
                Client.LogOut(session);
            }
        }

        private static void DumpVault(int index, VaultInfo vaultInfo, Session session)
        {
            Console.WriteLine("{0}: '{1}', '{2}':", index + 1, vaultInfo.Id, vaultInfo.Name);

            var vault = Client.OpenVault(vaultInfo, session);

            // Dump accounts
            for (var i = 0; i < vault.Accounts.Length; ++i)
            {
                var account = vault.Accounts[i];
                Console.WriteLine(
                    "  {0}:\n"
                        + "          id: {1}\n"
                        + "        name: {2}\n"
                        + "    username: {3}\n"
                        + "    password: {4}\n"
                        + "         url: {5}\n"
                        + "        note: {6}\n",
                    i + 1,
                    account.Id,
                    account.Name,
                    account.Username,
                    account.Password,
                    account.MainUrl,
                    account.Note
                );

                foreach (var otp in account.Otps)
                    Console.WriteLine("         otp: {0}: {1} (section: {2})", otp.Name, otp.Secret, otp.Section);
                foreach (var field in account.Fields)
                    Console.WriteLine("       field: {0}: {1} (section: {2})", field.Name, field.Value, field.Section);
            }

            // Dump SSH keys
            for (var i = 0; i < vault.SshKeys.Length; ++i)
            {
                var sshKey = vault.SshKeys[i];
                Console.WriteLine(
                    $"""
                    {i + 1}:
                                 name: {sshKey.Name}
                          description: {sshKey.Description}
                                  key: {sshKey.Key}
                          private key: {sshKey.PrivateKey}
                           public key: {sshKey.PublicKey}
                          fingerprint: {sshKey.Fingerprint}
                             key type: {sshKey.KeyType}
                                 note: {sshKey.Note}
                    """
                );
            }
        }
    }
}
