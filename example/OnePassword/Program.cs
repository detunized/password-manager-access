// Copyright (C) 2012-2019 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using PasswordManagerAccess.Common;
using PasswordManagerAccess.Example.Common;
using PasswordManagerAccess.OnePassword;

namespace Example
{
    public static class Program
    {
        private class TextUi: Ui
        {
            private const string ToCancel = "or just press ENTER to cancel";

            public override Passcode ProvideGoogleAuthPasscode()
            {
                return GetPasscode("Enter Google Authenticator passcode");
            }

            private static Passcode GetPasscode(string prompt)
            {
                var passcode = GetAnswer($"{prompt} {ToCancel}");
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

        // A primitive not-so-secure secure storage implementation. It stores a dictionary
        // as a list of strings in a text file. It could be JSON or something but we don't
        // want any extra dependencies.
        private class PlainStorage: ISecureStorage
        {
            public PlainStorage(string filename)
            {
                _filename = filename;

                var lines = File.Exists(filename) ? File.ReadAllLines(filename) : new string[0];
                for (var i = 0; i < lines.Length / 2; ++i)
                    _storage[lines[i * 2]] = lines[i * 2 + 1];
            }

            public void StoreString(string name, string value)
            {
                _storage[name] = value;
                Save();
            }

            public string LoadString(string name)
            {
                return _storage.ContainsKey(name) ? _storage[name] : null;
            }

            private void Save()
            {
                File.WriteAllLines(_filename, _storage.SelectMany(i => new[] { i.Key, i.Value }));
            }

            private readonly string _filename;
            private readonly Dictionary<string, string> _storage = new Dictionary<string, string>();
        }

        private class ConsoleLogger: ILogger
        {
            public void Log(DateTime timestamp, string text)
            {
                var originalColor = Console.ForegroundColor;
                Console.ForegroundColor = ConsoleColor.Green;

                try
                {
                    Console.WriteLine($"{timestamp}: {text}");
                }
                finally
                {
                    Console.ForegroundColor = originalColor;
                }
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
                DumpAllVaults(config["username"], config["password"], config["account-key"], config["device-id"], config["domain"]);
            }
            catch (ClientException e)
            {
                Console.WriteLine("Error: {0} (Reason: {1})", e.Message, e.Reason);
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
                                              new PlainStorage("../../storage.txt"),
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
