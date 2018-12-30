// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using Bitwarden;
using System;
using System.IO;

namespace Example
{
    public class Program
    {
        private class TextUi: Ui
        {
            private const string ToCancel = "or just press ENTER to cancel";

            public override string ProvideGoogleAuthCode()
            {
                return GetAnswer($"Please enter Google Authenticator code {ToCancel}");
            }

            public override string ProvideEmailCode(string email)
            {
                return GetAnswer($"Please check you email ({email}) and enter the code {ToCancel}");
            }

            public override string ProvideYubiKeyCode()
            {
                return GetAnswer($"Please enter the YubiKey code {ToCancel}");
            }

            public override (DuoDevice Device, DuoFactor Factor) ChooseDuoFactor(DuoDevice[] devices)
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
                        return (null, (DuoFactor)(-1)); // Factor doesn't matter, let's put garbage in it

                    if (int.TryParse(answer, out var choice))
                        foreach (var d in devices)
                            foreach (var f in d.Factors)
                                if (--choice == 0)
                                    return (d, f);

                    Console.WriteLine("Wrong input, try again");
                }
            }

            public override string ProvideDuoPasscode(DuoDevice device)
            {
                return GetAnswer($"Enter the passcode for {device.Name} {ToCancel}");
            }

            public override void UpdateDuoStatus(DuoStatus status, string text)
            {
                Console.WriteLine($"Duo {status}: {text}");
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
            // The file should contain 2 lines:
            //   - username
            //   - password
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            try
            {
                var vault = Vault.Open(username, password, new TextUi());
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
