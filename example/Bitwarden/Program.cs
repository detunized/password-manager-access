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
                deviceId = Vault.GenerateRandomDeviceId();
                Console.WriteLine($"Your newly generated device ID is {deviceId}. " + "Store it and use it for subsequent runs.");
            }

            // This one is optional
            var baseUrl = config.GetValueOrDefault("base-url", "");
            if (!string.IsNullOrEmpty(baseUrl))
                Console.WriteLine($"Using a custom base URL {baseUrl}");

            try
            {
                Vault vault;
                if (config.TryGetValue("client-id", out var clientId))
                {
                    // Fully non-interactive CLI/API mode
                    Console.WriteLine("Using the CLI/API mode");
                    vault = Vault.Open(
                        new ClientInfoCliApi(
                            clientId: clientId,
                            clientSecret: config["client-secret"],
                            password: config["password"],
                            deviceId: deviceId
                        ),
                        baseUrl
                    );
                }
                else
                {
                    // Possibly interactive browser mode
                    Console.WriteLine("Using the browser mode");
                    vault = Vault.Open(
                        new ClientInfoBrowser(username: config["username"], password: config["password"], deviceId: deviceId),
                        baseUrl: baseUrl,
                        ui: new TextUi(),
                        storage: new PlainStorage()
                    );
                }

                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];
                    Console.WriteLine(
                        "{0}:\n"
                            + "          id: {1}\n"
                            + "        name: {2}\n"
                            + "    username: {3}\n"
                            + "    password: {4}\n"
                            + "         url: {5}\n"
                            + "        note: {6}\n"
                            + "      folder: {7}\n",
                        i + 1,
                        account.Id,
                        account.Name,
                        account.Username,
                        account.Password,
                        account.Url,
                        account.Note,
                        account.Folder
                    );

                    if (account.CustomFields.Length > 0)
                    {
                        Console.WriteLine("    Custom fields:");
                        foreach (var f in account.CustomFields)
                            Console.WriteLine($"      - {f.Name}: {f.Value}");
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
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
