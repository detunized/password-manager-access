// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Linq;
using PasswordManagerAccess.Bitwarden;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;

namespace PasswordManagerAccess.Example.Keeper
{
    public static class Program
    {
        private class TextUi: Ui
        {
            private const string ToCancel = "or just press ENTER to cancel";

            public override void Close()
            {
            }

            public override MfaMethod ChooseMfaMethod(MfaMethod[] availableMethods)
            {
                var methods = availableMethods.Where(m => m != MfaMethod.Cancel).OrderBy(m => m).ToArray();
                var lines = methods.Select((m, i) => $"{i + 1} {m}");
                var prompt = $"Please choose the second factor method {ToCancel}\n\n" +
                             string.Join("\n", lines);

                while (true)
                {
                    var answer = GetAnswer(prompt);

                    // Blank means canceled by the user
                    if (string.IsNullOrWhiteSpace(answer))
                        return MfaMethod.Cancel;

                    int choice;
                    if (int.TryParse(answer, out choice))
                    {
                        choice--;
                        if (choice >= 0 && choice < methods.Length)
                            return methods[choice];
                    }

                    Console.WriteLine("Wrong input, try again");
                }
            }

            public override Passcode ProvideGoogleAuthPasscode()
            {
                return GetPasscode($"Please enter Google Authenticator code {ToCancel}");
            }

            public override Passcode ProvideEmailPasscode(string emailHint)
            {
                return GetPasscode($"Please check you email ({emailHint}) and enter the code {ToCancel}");
            }

            public override Passcode ProvideYubiKeyPasscode()
            {
                return GetPasscode($"Please enter the YubiKey code {ToCancel}");
            }

            public override Passcode ProvideU2fPasscode(string appId, byte[] challenge, byte[] keyHandle)
            {
                return new Passcode("TODO", false);
            }

            public override DuoChoice ChooseDuoFactor(DuoDevice[] devices)
            {
                var prompt = $"Choose a factor you want to use {ToCancel}:\n\n";
                var index = 1;
                foreach (var d in devices)
                {
                    prompt += $"{d.Name}\n";
                    foreach (var f in d.Factors)
                    {
                        prompt += $"  {index}. {f}\n";
                        index += 1;
                    }
                }

                while (true)
                {
                    var answer = GetAnswer(prompt);

                    // Blank means canceled by the user
                    if (string.IsNullOrWhiteSpace(answer))
                        return null;

                    int choice;
                    if (int.TryParse(answer, out choice))
                        foreach (var d in devices)
                            foreach (var f in d.Factors)
                                if (--choice == 0)
                                    return new DuoChoice(d, f, GetRememberMe());

                    Console.WriteLine("Wrong input, try again");
                }
            }

            public override string ProvideDuoPasscode(DuoDevice device)
            {
                return GetAnswer($"Enter the passcode for {device.Name} {ToCancel}");
            }

            public override void UpdateDuoStatus(DuoStatus status, string text)
            {
                switch (status)
                {
                case DuoStatus.Success:
                    Console.ForegroundColor = ConsoleColor.Green;
                    break;
                case DuoStatus.Error:
                    Console.ForegroundColor = ConsoleColor.Red;
                    break;
                case DuoStatus.Info:
                    Console.ForegroundColor = ConsoleColor.Blue;
                    break;
                }

                Console.WriteLine($"Duo {status}: {text}");
                Console.ResetColor();
            }

            private static Passcode GetPasscode(string prompt)
            {
                var passcode = GetAnswer(prompt);
                if (string.IsNullOrWhiteSpace(passcode))
                    return null;

                return new Passcode(passcode, GetRememberMe());
            }

            private static string GetAnswer(string prompt)
            {
                Console.WriteLine(prompt);
                Console.Write("> ");
                var input = Console.ReadLine();

                return input == null ? "" : input.Trim();
            }

            private static bool GetRememberMe()
            {
                var remember = GetAnswer("Remember this device?").ToLower();
                return remember == "y" || remember == "yes";
            }
        }

        public static void Main(string[] args)
        {
            var config = Util.ReadConfig();

            // The device is required. The first time it should be generated using
            // Vault.GenerateRandomDeviceId and stored for later reuse. It's not a
            // good idea to generate a new device ID on every run.
            var deviceId = config.ContainsKey("device-id") ? config["device-id"] : "";
            if (string.IsNullOrEmpty(deviceId))
            {
                deviceId = Vault.GenerateRandomDeviceId();
                Console.WriteLine($"Your newly generated device ID is {deviceId}. " +
                                  "Store it and use it for subsequent runs.");
            }

            // This one is optional
            var baseUrl = config.ContainsKey("base-url") ? config["base-url"] : "";
            if (!string.IsNullOrEmpty(baseUrl))
                Console.WriteLine($"Using a custom base URL {baseUrl}");

            try
            {
                var vault = Vault.Open(config["username"],
                                       config["password"],
                                       deviceId,
                                       baseUrl,
                                       new TextUi(),
                                       new PlainStorage());

                for (int i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];
                    Console.WriteLine("{0}:\n" +
                                      "          id: {1}\n" +
                                      "        name: {2}\n" +
                                      "    username: {3}\n" +
                                      "    password: {4}\n" +
                                      "         url: {5}\n" +
                                      "        note: {6}\n" +
                                      "      folder: {7}\n",
                                      i + 1,
                                      account.Id,
                                      account.Name,
                                      account.Username,
                                      account.Password,
                                      account.Url,
                                      account.Note,
                                      account.Folder);
                }
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }
    }
}
