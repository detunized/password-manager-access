// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Bitwarden;
using System;
using System.IO;
using System.Linq;

namespace Example
{
    public class Program
    {
        private class TextUi: Ui
        {
            private const string ToCancel = "or just press ENTER to cancel";

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

                    if (int.TryParse(answer, out var choice))
                        foreach (var d in devices)
                            foreach (var f in d.Factors)
                                if (--choice == 0)
                                    return new DuoChoice(d, f, false); // TODO: Ask to remember me

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

                var remember = GetAnswer("Remember this device?").ToLower();

                return new Passcode(passcode, remember == "y" || remember == "yes");
            }

            private static string GetAnswer(string prompt)
            {
                Console.WriteLine(prompt);
                Console.Write("> ");
                var input = Console.ReadLine();

                return input == null ? "" : input.Trim();
            }
        }

        public static void Main(string[] args)
        {
            // Read Bitwarden credentials from a file
            // The file should contain 2 or 3 lines:
            //   - username
            //   - password
            //   - device ID (optional)
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            // The device is required. The first time it should be generated using
            // Vault.GenerateRandomDeviceId and stored for later reuse. It's not a
            // good idea to generate a new device ID on every run.
            var deviceId = credentials.ElementAtOrDefault(2);
            if (string.IsNullOrWhiteSpace(deviceId))
            {
                deviceId = Vault.GenerateRandomDeviceId();
                Console.WriteLine($"Your newly generated device ID is {deviceId}. " +
                                  "Store it and use it for subsequent runs.");
            }

            try
            {
                var vault = Vault.Open(username, password, deviceId, new TextUi());
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
            catch (ClientException e)
            {
                Console.WriteLine(e);
            }
        }
    }
}
