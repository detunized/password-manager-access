// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using OnePassword;

namespace Example
{
    public class Program
    {
        class TextUi: Ui
        {
            private const string ToCancel = "or just press ENTER to cancel";

            public override string ProviceGoogleAuthenticatorCode()
            {
                return GetAnswer($"Enter Google Authenticator passcode {ToCancel}");
            }

            private static string GetAnswer(string prompt)
            {
                Console.WriteLine(prompt);
                Console.Write("> ");
                var input = Console.ReadLine();

                return input == null ? "" : input.Trim();
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

        public static void Main(string[] args)
        {
            // Read 1Password credentials from a file
            // The file should contain 5 lines:
            //   - username
            //   - password
            //   - account key
            //   - client UUID
            //   - API domain (my.1password.com, my.1password.eu or my.1password.ca)
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];
            var accountKey = credentials[2];
            var uuid = credentials[3];
            var domain = credentials[4];

            try
            {
                DumpAllVaults(username, password, accountKey, uuid, domain);
            }
            catch (ClientException e)
            {
                Console.WriteLine("Error: {0} (Reason: {1})", e.Message, e.Reason);
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
                                              new PlainStorage("../../storage.txt"));

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
                                      account.Url,
                                      account.Note);
                }
            }
        }
    }
}
