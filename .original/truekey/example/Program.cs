// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using TrueKey;

namespace Example
{
    class Program
    {
        private class TextUi: Ui
        {
            public override Answer AskToWaitForEmail(string email, Answer[] validAnswers)
            {
                var answer = AskForAnswer(string.Format(
                    "A verification email is sent to '{0}'.\n" +
                    "Please check the inbox, confirm and then press enter.\n" +
                    "Enter 'r' to resend the email to '{0}'.", email));

                switch (answer.ToLowerInvariant())
                {
                case "r":
                    return Answer.Resend;
                default:
                    return Answer.Check;
                }
            }

            public override Answer AskToWaitForOob(string name, string email, Answer[] validAnswers)
            {
                var answer = AskForAnswer(string.Format(
                    "A push message is sent to '{0}'.\n" +
                    "Please check, confirm and then press enter.\n" +
                    "Enter 'r' to resend the push message to '{0}'.\n" +
                    "Enter 'e' to send a verification email to '{1}' instead.", name, email));

                switch (answer.ToLowerInvariant())
                {
                case "r":
                    return Answer.Resend;
                case "e":
                    return Answer.Email;
                default:
                    return Answer.Check;
                }
            }

            public override Answer AskToChooseOob(string[] names, string email, Answer[] validAnswers)
            {
                var text = new List<string>(names.Length + 2)
                {
                    "Please choose the second factor method:"
                };
                text.AddRange(names.Select((name, index) => string.Format(
                    " - {0}: push message to '{1}'",
                    index + 1,
                    name)));
                text.Add(string.Format(" - e: verification email to '{0}'", email));

                for (;;)
                {
                    var answer = AskForAnswer(string.Join("\n", text));

                    if (answer == "e")
                        return Answer.Email;

                    int deviceIndex;
                    if (int.TryParse(answer, out deviceIndex))
                    {
                        deviceIndex -= 1;
                        if (deviceIndex >= 0 && deviceIndex < names.Length)
                            return Answer.Device0 + deviceIndex;
                    }

                    Console.WriteLine("Invalid input '{0}'", answer);
                }
            }

            private string AskForAnswer(string prompt)
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
                File.WriteAllLines(_filename, _storage.SelectMany(i => new[] {i.Key, i.Value}));
            }

            private readonly string _filename;
            private readonly Dictionary<string, string> _storage = new Dictionary<string, string>();
        }

        static void Main(string[] args)
        {
            // Read True Key credentials from a file
            // The file should contain 2 lines: username and password
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            // File backed secure storage that keeps things between sessions.
            var storage = new PlainStorage("../../storage.txt");

            // Log in, fetch data, parse it.
            var vault = Vault.Open(username, password, new TextUi(), storage);

            // Print all the accounts
            for (var i = 0; i < vault.Accounts.Length; ++i)
            {
                var account = vault.Accounts[i];
                Console.WriteLine(
                    "{0}: {1} {2} {3} {4} {5}",
                    i + 1,
                    account.Name,
                    account.Username,
                    account.Password,
                    account.Url,
                    account.Note);
            }
        }
    }
}
