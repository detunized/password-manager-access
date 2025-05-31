// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.Linq;
using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Bitwarden.Ui;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using MfaMethod = PasswordManagerAccess.Bitwarden.Ui.MfaMethod;

// ReSharper disable once CheckNamespace
namespace PasswordManagerAccess.Example.Bitwarden
{
    public static class Program
    {
        private class TextUi : DuoUi, IUi
        {
            public void Close() { }

            public MfaMethod ChooseMfaMethod(MfaMethod[] availableMethods)
            {
                var methods = availableMethods.Where(m => m != MfaMethod.Cancel).OrderBy(m => m).ToArray();
                var lines = methods.Select((m, i) => $"{i + 1} {m}");
                var prompt = $"Please choose the second factor method {PressEnterToCancel}\n\n" + string.Join("\n", lines);

                while (true)
                {
                    var answer = GetAnswer(prompt);

                    // Blank means canceled by the user
                    if (string.IsNullOrWhiteSpace(answer))
                        return MfaMethod.Cancel;

                    if (int.TryParse(answer, out var choice))
                    {
                        choice--;
                        if (choice >= 0 && choice < methods.Length)
                            return methods[choice];
                    }

                    Console.WriteLine("Wrong input, try again");
                }
            }

            public Passcode ProvideGoogleAuthPasscode()
            {
                return GetPasscode($"Please enter Google Authenticator code {PressEnterToCancel}");
            }

            public Passcode ProvideEmailPasscode(string emailHint)
            {
                return GetPasscode($"Please check you email ({emailHint}) and enter the code {PressEnterToCancel}");
            }

            public Passcode ProvideYubiKeyPasscode()
            {
                return GetPasscode($"Please enter the YubiKey code {PressEnterToCancel}");
            }

            //
            // Private
            //

            private static Passcode GetPasscode(string prompt)
            {
                var passcode = GetAnswer(prompt);
                return string.IsNullOrWhiteSpace(passcode) ? null : new Passcode(passcode, GetRememberMe());
            }
        }

        public static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            // The device is required. The first time it should be generated using
            // Vault.GenerateRandomDeviceId and stored for later reuse. It's not a
            // good idea to generate a new device ID on every run.
            var deviceId = config.GetValueOrDefault("device-id", "");
            if (string.IsNullOrEmpty(deviceId))
            {
                deviceId = Client.GenerateRandomDeviceId();
                Console.WriteLine($"Your newly generated device ID is {deviceId}. " + "Store it and use it for subsequent runs.");
            }

            // This one is optional
            var baseUrl = config.GetValueOrDefault("base-url", "");
            if (!string.IsNullOrEmpty(baseUrl))
                Console.WriteLine($"Using a custom base URL {baseUrl}");

            try
            {
                // Choose either a single call to Vault.Open or a sequence of LogIn, DownloadVault, and LogOut.
                var useVaultOpen = false;
                if (useVaultOpen)
                {
                    UseOpen(config, deviceId, baseUrl);
                }
                else
                {
                    UseLoginDownloadLogout(config, deviceId, baseUrl);
                }
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }

        private static void UseLoginDownloadLogout(Dictionary<string, string> config, string deviceId, string baseUrl)
        {
            Session session;

            if (config.TryGetValue("client-id", out var clientId))
            {
                // Fully non-interactive CLI/API mode
                Console.WriteLine("Using the CLI/API mode with manual sequence");
                session = Client.LogIn(
                    new ClientInfoCliApi(clientId: clientId, clientSecret: config["client-secret"], password: config["password"], deviceId: deviceId),
                    baseUrl
                );
            }
            else
            {
                // Possibly interactive browser mode
                Console.WriteLine("Using the browser mode with manual sequence");
                session = Client.LogIn(
                    new ClientInfoBrowser(username: config["username"], password: config["password"], deviceId: deviceId),
                    baseUrl: baseUrl,
                    ui: new TextUi(),
                    storage: new PlainStorage()
                );
            }

            // Enable this to get a single item from a vault
            var getSingleItem = true;

            try
            {
                if (getSingleItem)
                {
                    // Get a single item from the vault (Account)
                    var item1 = Client.GetItem("25e95b65-aa73-40b4-af02-b2ee0079daa5", session);

                    // Use the old-school switch statement to match the item type
                    switch (item1.Value)
                    {
                        case Account account:
                            PrintAccount(account);
                            break;
                        case SshKey sshKey:
                            PrintSshKey(sshKey);
                            break;
                        case NoItem noItem:
                            Console.WriteLine($"No item found: {noItem}");
                            break;
                    }

                    // Get another item with the same session (SshKey)
                    var item2 = Client.GetItem("318df280-7880-4e4f-a965-b2e901549751", session);

                    // Can also use the OneOf.Switch method
                    item2.Switch(PrintAccount, PrintSshKey, noItem => Console.WriteLine($"No item found: {noItem}"));
                }
                else
                {
                    // Download vault data
                    var vault = Client.DownloadVault(session);

                    // Display the data
                    DumpVault(vault);
                }
            }
            finally
            {
                // Always log out to clean up resources
                Client.LogOut(session);
            }
        }

        private static void UseOpen(Dictionary<string, string> config, string deviceId, string baseUrl)
        {
            Vault vault;

            if (config.TryGetValue("client-id", out var clientId))
            {
                // Fully non-interactive CLI/API mode
                Console.WriteLine("Using the CLI/API mode with Vault.Open");
                vault = Client.Open(
                    new ClientInfoCliApi(clientId: clientId, clientSecret: config["client-secret"], password: config["password"], deviceId: deviceId),
                    baseUrl
                );
            }
            else
            {
                // Possibly interactive browser mode
                Console.WriteLine("Using the browser mode with Vault.Open");
                vault = Client.Open(
                    new ClientInfoBrowser(username: config["username"], password: config["password"], deviceId: deviceId),
                    baseUrl: baseUrl,
                    ui: new TextUi(),
                    storage: new PlainStorage()
                );
            }

            // Display the data
            DumpVault(vault);
        }

        private static void DumpVault(Vault vault)
        {
            for (var i = 0; i < vault.Accounts.Length; ++i)
            {
                Console.WriteLine($"Account {i + 1}:");
                PrintAccount(vault.Accounts[i]);
            }

            if (vault.SshKeys.Length > 0)
            {
                for (var i = 0; i < vault.SshKeys.Length; ++i)
                {
                    Console.WriteLine($"SSH Key {i + 1}:");
                    PrintSshKey(vault.SshKeys[i]);
                }
            }

            if (vault.Collections.Length > 0)
            {
                Console.WriteLine("Collections:");
                foreach (var c in vault.Collections)
                    Console.WriteLine($"  - id: {c.Id}, name: {c.Name}, org: {c.OrganizationId}, hide passwords: {c.HidePasswords}");
            }

            if (vault.Organizations.Length > 0)
            {
                Console.WriteLine("Organizations:");
                foreach (var o in vault.Organizations)
                    Console.WriteLine($"  - id: {o.Id}, name: {o.Name}");
            }

            if (vault.ParseErrors.Length > 0)
            {
                Console.WriteLine("Parse errors:");
                foreach (var e in vault.ParseErrors)
                    Console.WriteLine($"  - error: {e.Description}");
            }
        }

        private static void PrintAccount(Account account)
        {
            Console.WriteLine(
                $"""
                          id: {account.Id}
                        name: {account.Name}
                    username: {account.Username}
                    password: {account.Password}
                         url: {account.Url}
                        note: {ToSingleLine(account.Note, 100)}
                      folder: {account.Folder}
                """
            );

            PrintCustomFields(account);
        }

        private static void PrintSshKey(SshKey sshKey)
        {
            Console.WriteLine(
                $"""
                          id: {sshKey.Id}
                        name: {sshKey.Name}
                  public key: {ToSingleLine(sshKey.PublicKey, 100)}
                 private key: {ToSingleLine(sshKey.PrivateKey, 100)}
                 fingerprint: {sshKey.Fingerprint}
                        note: {ToSingleLine(sshKey.Note, 100)}
                      folder: {sshKey.Folder}
                """
            );

            PrintCustomFields(sshKey);
        }

        private static void PrintCustomFields(VaultItem item)
        {
            if (item.CustomFields.Length > 0)
            {
                Console.WriteLine("      custom fields:");
                foreach (var f in item.CustomFields)
                    Console.WriteLine($"      - {f.Name}: {f.Value}");
            }
        }

        private static string ToSingleLine(string s, int maxLength)
        {
            var line = s.Replace("\r\n", " ").Replace("\n", " ").Trim();
            return line.Length > maxLength ? line[..maxLength] + "..." : line;
        }
    }
}
