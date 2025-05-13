// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.OnePassword;
using PasswordManagerAccess.OnePassword.Ui;

namespace Example
{
    public static class Program
    {
        private class TextUi : DuoAsyncUi, IAsyncUi
        {
            public async Task<Passcode> ProvideGoogleAuthPasscode(CancellationToken cancellationToken)
            {
                var passcode = await GetAnswer($"Enter Google Authenticator passcode {PressEnterToCancel}", cancellationToken).ConfigureAwait(false);
                return string.IsNullOrWhiteSpace(passcode)
                    ? Passcode.Cancel
                    : new Passcode(passcode, await GetRememberMe(cancellationToken).ConfigureAwait(false));
            }

            public async Task<Passcode> ProvideWebAuthnRememberMe(CancellationToken cancellationToken)
            {
                var yesNo = (await GetAnswer($"Remember this device? {PressEnterToCancel}", cancellationToken).ConfigureAwait(false)).ToLower();
                return string.IsNullOrWhiteSpace(yesNo) ? Passcode.Cancel : new Passcode("", yesNo == "y" || yesNo == "yes");
            }
        }

        public static async Task Main()
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

            try
            {
                await DumpAllVaults(
                        config["username"],
                        config.GetValueOrDefault("password", ""),
                        config.GetValueOrDefault("account-key", ""),
                        config.GetValueOrDefault("domain", ""),
                        config["device-id"],
                        config.GetValueOrDefault("service-account-token", "")
                    )
                    .ConfigureAwait(false);
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }

        private static async Task DumpAllVaults(
            string username,
            string password,
            string accountKey,
            string domain,
            string uuid,
            string serviceAccountToken
        )
        {
            var device = new AppInfo { Name = "PMA 1Password example", Version = "1.0.0" };

            Session session;
            if (await Client.IsSsoAccount(username, CancellationToken.None).ConfigureAwait(false))
            {
                session = await Client
                    .SsoLogIn(
                        new Credentials { Username = username, DeviceUuid = uuid },
                        device,
                        new TextUi(),
                        new PlainStorage(),
                        CancellationToken.None
                    )
                    .ConfigureAwait(false);
            }
            else if (string.IsNullOrEmpty(serviceAccountToken))
            {
                session = await Client
                    .LogIn(
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
                        new PlainStorage(),
                        CancellationToken.None
                    )
                    .ConfigureAwait(false);
            }
            else
            {
                session = await Client
                    .LogIn(new ServiceAccount { Token = serviceAccountToken }, device, CancellationToken.None)
                    .ConfigureAwait(false);
            }

            // Enable this to get a single item from a vault
            var getSingleItem = false;

            // Enable this to get a single item from a vault
            var getSingleItem = false;

            try
            {
                if (getSingleItem)
                {
                    await GetSingleItem(session).ConfigureAwait(false);
                }
                else
                {
                    var vaults = await Client.ListAllVaults(session, CancellationToken.None).ConfigureAwait(false);

                    for (var i = 0; i < vaults.Length; i++)
                    {
                        await DumpVault(i, vaults[i], session).ConfigureAwait(false);
                    }
                }
            }
            finally
            {
                await Client.LogOut(session, CancellationToken.None).ConfigureAwait(false);
            }
        }

        private static async Task DumpVault(int index, VaultInfo vaultInfo, Session session)
        {
            Console.WriteLine($"Vault {index + 1} '{vaultInfo.Id}', '{vaultInfo.Name}':");

            var vault = await Client.OpenVault(vaultInfo, session, CancellationToken.None).ConfigureAwait(false);

            // Dump accounts
            for (var i = 0; i < vault.Accounts.Length; ++i)
                DumpAccount($"{i + 1}", vault.Accounts[i]);

            // Dump SSH keys
            for (var i = 0; i < vault.SshKeys.Length; ++i)
                DumpSshKey($"{i + 1}", vault.SshKeys[i]);
        }

        private static async Task GetSingleItem(Session session)
        {
            // TODO: Use your own vault and item IDs, this is just an example.
            var item = await Client
                .GetItem("bg4djajw227j7j5hknmwrzzbam", "vdwyrtrrg3suzcw4pn6ydmhsga", session, CancellationToken.None)
                .ConfigureAwait(false);
            item.Switch(account => DumpAccount("1", account), sshKey => DumpSshKey("1", sshKey), noItem => Console.WriteLine($"No item: {noItem}"));
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
