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
        private class TextUi: DuoUi, IUi
        {
            public Passcode ProvideGoogleAuthPasscode()
            {
                var passcode = GetAnswer($"Enter Google Authenticator passcode {PressEnterToCancel}");
                return string.IsNullOrWhiteSpace(passcode)
                    ? Passcode.Cancel
                    : new Passcode(passcode, GetRememberMe());
            }
        }

        private class ConsoleLogger: ILogger
        {
            public void Log(DateTime timestamp, string text)
            {
                Util.WriteLine($"{timestamp}: {text}", ConsoleColor.Green);
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

            try
            {
                DumpAllVaults(config["username"],
                              config["password"],
                              config["account-key"],
                              config["device-id"],
                              config["domain"]);
            }
            catch (BaseException e)
            {
                Util.PrintException(e);
            }
        }

        private static void DumpAllVaults(string username,
                                          string password,
                                          string accountKey,
                                          string uuid,
                                          string domain)
        {
            var vaults = Client.OpenAllVaults(username,
                                              password,
                                              accountKey,
                                              uuid,
                                              domain,
                                              new TextUi(),
                                              new PlainStorage(),
                                              new ConsoleLogger());

            foreach (var vault in vaults)
            {
                Console.WriteLine("{0}: '{1}', '{2}':", vault.Id, vault.Name, vault.Description);
                for (int i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];
                    Console.WriteLine("  {0}:\n" +
                                      "          id: {1}\n" +
                                      "        name: {2}\n" +
                                      "    username: {3}\n" +
                                      "    password: {4}\n" +
                                      "         url: {5}\n" +
                                      "        note: {6}\n",
                                      i + 1,
                                      account.Id,
                                      account.Name,
                                      account.Username,
                                      account.Password,
                                      account.MainUrl,
                                      account.Note);
                }
            }
        }
    }
}
