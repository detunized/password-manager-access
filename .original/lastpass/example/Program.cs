// Copyright (C) 2013 Dmitry Yakimenko (detunized@gmail.com).
// Licensed under the terms of the MIT license. See LICENCE for details.

using System;
using System.IO;
using LastPass;

namespace Example
{
    class Program
    {
        // Very simple text based user interface that demonstrates how to respond to
        // to Vault UI requests.
        private class TextUi: Ui
        {
            public override string ProvideSecondFactorPassword(SecondFactorMethod method)
            {
                return GetAnswer(string.Format("Please enter {0} code", method));
            }

            public override void AskToApproveOutOfBand(OutOfBandMethod method)
            {
                Console.WriteLine("Please approve out-of-band via {0} and press ENTER", method);
            }

            private static string GetAnswer(string prompt)
            {
                Console.WriteLine(prompt);
                Console.Write("> ");
                var input = Console.ReadLine();

                return input == null ? "" : input.Trim();
            }
        }

        static void Main(string[] args)
        {
            // Read LastPass credentials from a file
            // The file should contain 2 lines: username and password.
            // See credentials.txt.example for an example.
            var credentials = File.ReadAllLines("../../credentials.txt");
            var username = credentials[0];
            var password = credentials[1];

            try
            {
                // Fetch and create the vault from LastPass
                var vault = Vault.Create(username, password, new TextUi());

                // Dump all the accounts
                for (var i = 0; i < vault.Accounts.Length; ++i)
                {
                    var account = vault.Accounts[i];
                    Console.WriteLine("{0}: {1} {2} {3} {4} {5} {6}",
                                      i + 1,
                                      account.Id,
                                      account.Name,
                                      account.Username,
                                      account.Password,
                                      account.Url,
                                      account.Group);
                }
            }
            catch (LoginException e)
            {
                Console.WriteLine("Something went wrong: {0}", e);
            }
        }
    }
}
