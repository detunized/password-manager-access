// Copyright (C) Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

#nullable enable

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Threading;
using System.Threading.Tasks;
using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Bitwarden.Ui;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;

// ReSharper disable once CheckNamespace
namespace PasswordManagerAccess.Example.Bitwarden
{
    public class TextUi : IAsyncUi
    {
        public Task<Canceled?> OpenInBrowser(string url, CancellationToken cancellationToken)
        {
            OpenUrl(url);
            return Task.FromResult<Canceled?>(null);
        }

        public Task CloseBrowser(bool success, CancellationToken cancellationToken)
        {
            Console.WriteLine("You can now close the browser.");
            return Task.CompletedTask;
        }

        private static void OpenUrl(string url)
        {
            Console.WriteLine($"Opening URL {url} in the default browser...");

            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.OSX))
                Process.Start("open", url);
            else if (RuntimeInformation.IsOSPlatform(OSPlatform.Linux))
                Process.Start("xdg-open", url);
            else
                throw new PlatformNotSupportedException("Unsupported OS");
        }
    }

    public static class Program
    {
        public static async Task Main(string[] args)
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
            var baseUrl = config.GetValueOrDefault("base-url", Client.DefaultBaseUlr);
            if (!string.IsNullOrEmpty(baseUrl))
                Console.WriteLine($"Using a custom base URL {baseUrl}");

            try
            {
                // Choose either a single call to Vault.Open or a sequence of LogIn, DownloadVault, and LogOut.
                var useVaultOpen = false;
                if (useVaultOpen)
                {
                    await UseOpen(config, deviceId, baseUrl);
                }
                else
                {
                    await UseLoginDownloadLogout(config, deviceId, baseUrl);
                }
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }

        private static async Task UseLoginDownloadLogout(Dictionary<string, string> config, string deviceId, string baseUrl)
        {
            // Fully non-interactive CLI/API mode
            Console.WriteLine("Using the CLI/API mode with manual sequence");

            // To differentiate an SSO from a regular login, provide the organization ID.
            // There doesn't seem to be a way to check if a specific username is an SSO user, like with other services.
            var isSso = config.TryGetValue("organization", out var organization) && !string.IsNullOrEmpty(organization);

            var session = isSso
                ? await Client.LogInSso(
                    new ClientInfoSso
                    {
                        Password = config["password"],
                        DeviceId = deviceId,
                        Organization = organization!,
                    },
                    baseUrl,
                    new TextUi(),
                    CancellationToken.None
                )
                : await Client.LogIn(
                    new ClientInfoCliApi
                    {
                        ClientId = config["client-id"],
                        ClientSecret = config["client-secret"],
                        Password = config["password"],
                        DeviceId = deviceId,
                    },
                    baseUrl,
                    CancellationToken.None
                );

            // Enable this to get a single item from a vault
            var getSingleItem = false;

            try
            {
                if (getSingleItem)
                {
                    // Get a single item from the vault (Account)
                    var item1 = await Client.GetItem("25e95b65-aa73-40b4-af02-b2ee0079daa5", session, CancellationToken.None);

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
                    var item2 = await Client.GetItem("318df280-7880-4e4f-a965-b2e901549751", session, CancellationToken.None);

                    // Can also use the OneOf.Switch method
                    item2.Switch(PrintAccount, PrintSshKey, noItem => Console.WriteLine($"No item found: {noItem}"));
                }
                else
                {
                    // Download vault data
                    var vault = await Client.DownloadVault(session, CancellationToken.None);

                    // Display the data
                    DumpVault(vault);
                }
            }
            finally
            {
                // Always log out to clean up resources
                await Client.LogOut(session, CancellationToken.None);
            }
        }

        private static async Task UseOpen(Dictionary<string, string> config, string deviceId, string baseUrl)
        {
            // Fully non-interactive CLI/API mode
            Console.WriteLine("Using the CLI/API mode with Vault.Open");

            if (!config.TryGetValue("client-id", out var clientId))
            {
                Console.WriteLine("Error: client-id is required. Browser mode has been removed.");
                Console.WriteLine("Please configure client-id and client-secret in your config.yaml");
                return;
            }

            var vault = await Client.Open(
                new ClientInfoCliApi
                {
                    ClientId = clientId,
                    ClientSecret = config["client-secret"],
                    Password = config["password"],
                    DeviceId = deviceId,
                },
                baseUrl,
                CancellationToken.None
            );

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
