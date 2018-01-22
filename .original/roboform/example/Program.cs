// Copyright (C) 2017 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using RoboForm;

namespace Example
{
    class Program
    {
        private class TextUi: Ui
        {
            public override SecondFactorPassword ProvideSecondFactorPassword(string kind)
            {
                var password = GetAnswer(
                    string.Format("Please provide the second factor code ({0})", kind));
                var remember = GetAnswer("Remember this device (y/n)?").ToLowerInvariant();

                return new SecondFactorPassword(password, remember == "y" || remember == "yes");
            }

            private static string GetAnswer(string prompt)
            {
                Console.WriteLine(prompt);
                Console.Write("> ");
                var input = Console.ReadLine();

                return input == null ? "" : input.Trim();
            }
        }

        private static void Main(string[] args)
        {
            // Read RoboForm credentials from a file
            // The file should contain 3 lines: username, password and device id
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];
            var deviceId = credentials[2];

            try
            {
                var vault = Vault.Open(username, password, deviceId, new TextUi());
                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var a = vault.Accounts[i];

                    Console.WriteLine("{0}: {1} {2} {3}", i + 1, a.Name, a.Path, a.Url);

                    foreach (var field in a.Fields)
                        Console.WriteLine("  - {0}: {1}", field.Name, field.Value);

                    if (a.GuessedUsername != null)
                        Console.WriteLine("  * guessed username: {0}", a.GuessedUsername);

                    if (a.GuessedPassword != null)
                        Console.WriteLine("  * guessed password: {0}", a.GuessedPassword);
                }
            }
            catch (BaseException e)
            {
                Console.WriteLine("Error: {0}", e);
            }
        }
    }
}
