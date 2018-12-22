// Copyright (C) 2018 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using Bitwarden;

namespace Example
{
    public class Program
    {
        private class TextUi: Ui
        {
            public override string ProvideGoogleAuthCode()
            {
                return GetAnswer("Please enter Google Authenticator code");
            }

            public override string ProvideEmailCode(string email)
            {
                return GetAnswer($"Please check you email ({email}) and enter the code");
            }

            public override string ProvideYubiKeyCode()
            {
                return GetAnswer("Please enter the YubiKey code");
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
