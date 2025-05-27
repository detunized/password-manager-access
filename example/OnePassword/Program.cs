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

            // Enable this to get a single item from a vault
            var getSingleItem = false;

            try
            {
                if (getSingleItem)
                {
                    GetSingleItem(session);
                }
                else
                {
                    var vaults = Client.ListAllVaults(session);

                    for (var i = 0; i < vaults.Length; i++)
                        DumpVault(i, vaults[i], session);
                }
            }
            finally
            {
                Client.LogOut(session);
            }
        }

        private static void DumpVault(int index, VaultInfo vaultInfo, Session session)
        {
            Console.WriteLine($"Vault {index + 1} '{vaultInfo.Id}', '{vaultInfo.Name}':");

            var vault = Client.OpenVault(vaultInfo, session);

            // Dump accounts
            for (var i = 0; i < vault.Accounts.Length; ++i)
                DumpAccount($"{i + 1}", vault.Accounts[i]);

            // Dump SSH keys
            for (var i = 0; i < vault.SshKeys.Length; ++i)
                DumpSshKey($"{i + 1}", vault.SshKeys[i]);
        }

        private static void GetSingleItem(Session session)
        {
            // TODO: Use your own vault and item IDs, this is just an example.
            Client
                .GetItem("bg4djajw227j7j5hknmwrzzbam", "vdwyrtrrg3suzcw4pn6ydmhsga", session)
                .Switch(account => DumpAccount("1", account), sshKey => DumpSshKey("1", sshKey), noItem => Console.WriteLine($"No item: {noItem}"));
        }

        private static void DumpAccount(string name, Account account)
        {
            Console.WriteLine(
                $"""
                Account {name}:
                               id: {account.Id}
                             name: {account.Name}
                         username: {account.Username}
                         password: {account.Password}
                              url: {account.MainUrl}
                             note: {account.Note}
                """
            );

            foreach (var url in account.Urls)
                Console.WriteLine($"              url: {url.Name}: {url.Value}");

            foreach (var otp in account.Otps)
                Console.WriteLine($"              otp: {otp.Name}: {otp.Secret} (section: {otp.Section})");

            foreach (var field in account.Fields)
                Console.WriteLine($"            field: {field.Name}: {field.Value} (section: {field.Section})");
        }

        private static void DumpSshKey(string name, SshKey sshKey)
        {
            Console.WriteLine(
                $"""
                SSH key {name}:
                               id: {sshKey.Id}
                             name: {sshKey.Name}
                      description: {sshKey.Description}
                      private key: {Shorten(sshKey.PrivateKey)}
                       public key: {Shorten(sshKey.PublicKey)}
                      fingerprint: {sshKey.Fingerprint}
                         key type: {sshKey.KeyType}
                             note: {sshKey.Note}
                         original: {Shorten(sshKey.GetPrivateKey(SshKeyFormat.Original))}
                          OpenSSH: {Shorten(sshKey.GetPrivateKey(SshKeyFormat.OpenSsh))}
                           PKCS#8: {Shorten(sshKey.GetPrivateKey(SshKeyFormat.Pkcs8))}
                           PKCS#1: {Shorten(sshKey.GetPrivateKey(SshKeyFormat.Pkcs1))}
                """
            );

            foreach (var field in sshKey.Fields)
                Console.WriteLine($"            field: '{field.Name}' = '{Shorten(field.Value)}' (section: '{field.Section}')");

            static string Shorten(string s, int length = 80)
            {
                s = s.Replace("\n", "").Replace("\r", "");
                if (s.Length < length)
                    return s;

                return s.Substring(0, length - 3) + "...";
            }
        }
    }
}
